"""Runtime-only, encrypted source accounts and origin-scoped HTTP sessions."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from . import database

USER_AGENT = "ResearchIndex/0.1 (+local metadata research; contact: local-user)"
_key_lock = threading.Lock()
_locks_guard = threading.Lock()
_locks: dict[int, threading.RLock] = {}
_next_request: dict[int, float] = {}


class SourceAuthError(RuntimeError):
    pass


class SourceHTTPError(RuntimeError):
    def __init__(self, code: int, headers) -> None:
        self.code = code
        self.headers = headers
        super().__init__(f"Source returned HTTP {code}")


def source_lock(source_id: int) -> threading.RLock:
    with _locks_guard:
        return _locks.setdefault(source_id, threading.RLock())


def _cipher() -> Fernet:
    key = os.getenv("SOURCE_SECRETS_KEY")
    if key:
        return Fernet(key.encode())
    path = database.DB_PATH.parent / "source-secrets.key"
    with _key_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(Fernet.generate_key())
        return Fernet(path.read_bytes())


def _read(row) -> dict[str, Any]:
    try:
        return json.loads(_cipher().decrypt(row["secret"].encode()))
    except (InvalidToken, ValueError, OSError) as error:
        raise SourceAuthError(
            "Cannot decrypt source login. Restore the runtime key or replace the saved login."
        ) from error


def _write(
    db, source_id: int, config: dict[str, Any], error: str | None = None
) -> None:
    secret = _cipher().encrypt(json.dumps(config).encode()).decode()
    db.execute(
        """INSERT INTO source_auth(source_id, mode, secret, last_error) VALUES (?, ?, ?, ?)
                  ON CONFLICT(source_id) DO UPDATE SET mode=excluded.mode, secret=excluded.secret, last_error=excluded.last_error""",
        (source_id, config["mode"], secret, error),
    )


def public_auth(db, source_id: int) -> dict[str, Any]:
    row = db.execute(
        "SELECT mode, last_error FROM source_auth WHERE source_id=?", (source_id,)
    ).fetchone()
    return {
        "mode": row["mode"] if row else "none",
        "last_error": row["last_error"] if row else None,
    }


def save_auth(
    db,
    source_id: int,
    mode: str,
    username: str | None,
    password: str | None,
    cookie: str | None,
) -> None:
    if mode == "none":
        db.execute("DELETE FROM source_auth WHERE source_id=?", (source_id,))
        return
    row = db.execute(
        "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
    ).fetchone()
    # A complete replacement can recover from a lost key without decrypting old data.
    replacement = bool(username and password) if mode == "password" else bool(cookie)
    old = _read(row) if row and row["mode"] == mode and not replacement else {}
    config: dict[str, Any] = {"mode": mode, "cookies": []}
    if mode == "password":
        config.update(
            username=username or old.get("username"),
            password=password or old.get("password"),
        )
        if not config["username"] or not config["password"]:
            raise ValueError("A username and password are required for automatic login")
    elif mode == "cookie":
        header = cookie or old.get("cookie")
        if not header or any(ord(c) < 32 or ord(c) > 126 for c in header):
            raise ValueError("Paste a valid browser Cookie request header")
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except Exception as error:
            raise ValueError("Paste a valid browser Cookie request header") from error
        if not parsed:
            raise ValueError("Paste a valid browser Cookie request header")
        config["cookie"] = header
    else:
        raise ValueError("Unknown login mode")
    _write(db, source_id, config)


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return (
        parsed.scheme,
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: str) -> None:
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) != _origin(self.origin):
            raise SourceAuthError(
                "Source redirected to another origin. Check the configured source URL."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _cookie(name: str, value: str, host: str) -> http.cookiejar.Cookie:
    return http.cookiejar.Cookie(
        0,
        name,
        value,
        None,
        False,
        host,
        False,
        False,
        "/",
        True,
        True,
        None,
        True,
        None,
        None,
        {},
    )


def _logged_in(html: str) -> bool:
    return bool(re.search(r"\bid\s*=\s*['\"]logged-in-username['\"]", html, re.I))


def fetch_source_html(
    source_id: int, url: str, adapter: dict[str, Any]
) -> tuple[str, int]:
    with source_lock(source_id):
        with database.connect() as db:
            source = db.execute(
                "SELECT * FROM sources WHERE id=?", (source_id,)
            ).fetchone()
            row = db.execute(
                "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
            ).fetchone()
        if not source:
            raise SourceAuthError("Source no longer exists")
        if not row:
            if source["kind"] == "rutracker":
                raise SourceAuthError(
                    "Configure an account or browser session in Edit source first."
                )
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"}
            )
            with urllib.request.urlopen(request, timeout=25) as response:
                return response.read().decode(
                    response.headers.get_content_charset()
                    or adapter.get("response_charset", "utf-8"),
                    errors="replace",
                ), response.status
        if row["last_error"]:
            raise SourceAuthError(row["last_error"])
        if _origin(url) != _origin(source["base_url"]) or _origin(url)[0] != "https":
            raise SourceAuthError(
                "Authenticated requests require HTTPS on the configured source origin."
            )
        config = _read(row)
        jar = http.cookiejar.CookieJar()
        for item in config.get("cookies", []):
            jar.set_cookie(http.cookiejar.Cookie(**item))
        if not config.get("cookies") and config["mode"] == "cookie":
            cookies = SimpleCookie()
            cookies.load(config["cookie"])
            for name, morsel in cookies.items():
                jar.set_cookie(
                    _cookie(name, morsel.value, urllib.parse.urlsplit(url).hostname)
                )
        opener = urllib.request.build_opener(
            _SameOriginRedirect(source["base_url"]),
            urllib.request.HTTPCookieProcessor(jar),
        )

        def request(target: str, data: bytes | None = None) -> tuple[str, int]:
            pause = _next_request.get(source_id, 0) - time.monotonic()
            if pause > 0:
                time.sleep(pause)
            req = urllib.request.Request(
                target,
                data=data,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html",
                    "Referer": source["base_url"],
                },
            )
            try:
                with opener.open(req, timeout=25) as response:
                    return response.read().decode(
                        response.headers.get_content_charset()
                        or adapter.get("response_charset", "utf-8"),
                        errors="replace",
                    ), response.status
            except urllib.error.HTTPError as error:
                if error.code == 401:
                    return "", 401
                raise SourceHTTPError(error.code, error.headers) from error
            except urllib.error.URLError as error:
                raise RuntimeError("Could not reach the configured source") from error
            finally:
                _next_request[source_id] = (
                    time.monotonic() + source["current_delay_seconds"]
                )

        try:
            html, status = request(url)
            if not _logged_in(html):
                if config["mode"] == "cookie":
                    raise SourceAuthError(
                        "Browser session expired or was rejected. Log in in your browser and replace the Cookie header in Edit source."
                    )
                if re.search(r"cap_sid|cap_code_|/captcha/", html, re.I):
                    raise SourceAuthError(
                        "Source requires a CAPTCHA. Log in in your browser and use Browser session cookie in Edit source."
                    )
                login_url = urllib.parse.urljoin(
                    source["base_url"].rstrip("/") + "/", "forum/login.php"
                )
                try:
                    body = urllib.parse.urlencode(
                        {
                            "login_username": config["username"],
                            "login_password": config["password"],
                            "login": "Login",
                        },
                        encoding=adapter.get("response_charset", "utf-8"),
                    ).encode("ascii")
                except UnicodeEncodeError as error:
                    raise SourceAuthError(
                        "Credentials use characters unsupported by this source. Use a browser session cookie."
                    ) from error
                login_html, _ = request(login_url, body)
                if not _logged_in(login_html):
                    raise SourceAuthError(
                        "Login failed or requires a CAPTCHA. Check credentials, or log in in your browser and use Browser session cookie."
                    )
                html, status = request(url)
                if not _logged_in(html):
                    raise SourceAuthError(
                        "Login did not grant source access. Use a fresh browser session cookie."
                    )
        except SourceAuthError as error:
            with database.connect() as db:
                db.execute(
                    "UPDATE source_auth SET last_error=? WHERE source_id=?",
                    (str(error), source_id),
                )
            raise
        config["cookies"] = [
            {
                **{
                    key: getattr(c, key)
                    for key in (
                        "version",
                        "name",
                        "value",
                        "port",
                        "port_specified",
                        "domain",
                        "domain_specified",
                        "domain_initial_dot",
                        "path",
                        "path_specified",
                        "secure",
                        "expires",
                        "discard",
                        "comment",
                        "comment_url",
                    )
                },
                "rest": c._rest,
            }
            for c in jar
        ]
        with database.connect() as db:
            _write(db, source_id, config)
        return html, status
