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
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from . import database
from .browser_headers import extract_request_headers, validate_browser_headers

USER_AGENT = "ResearchIndex/0.1 (+local metadata research; contact: local-user)"
_key_lock = threading.Lock()
_locks_guard = threading.Lock()
_locks: dict[int, threading.RLock] = {}
_next_request: dict[int, float] = {}


class SourceAuthError(RuntimeError):
    pass


class SourceHTTPError(RuntimeError):
    def __init__(self, code: int, headers, phase: str | None = None) -> None:
        self.code = code
        self.headers = headers
        self.phase = phase
        message = f"Source returned HTTP {code}" + (f" while {phase}" if phase else "")
        if code == 403:
            message += ". Access was refused; this does not establish that the account password is wrong. Browser access may use different session state or request handling."
            if headers and headers.get("X-Mitmproxy-Blocked-Reason"):
                reason = headers.get("X-Mitmproxy-Blocked-Reason", "").upper()
                label = (
                    reason
                    if reason
                    in {
                        "ROBOTS_DENIED",
                        "BLOCK_LIST",
                        "HOST_NOT_ALLOWED",
                        "CONTENT_POLICY",
                    }
                    else "an access policy"
                )
                message += (
                    f" Response headers identify a network proxy denial ({label})."
                )
            elif headers and headers.get("CF-Mitigated", "").lower() == "challenge":
                message += " The response explicitly identifies a browser-verification challenge."
        super().__init__(message)


@dataclass(frozen=True)
class CookieHeader:
    header: str
    count: int


def parse_cookie_header(value: str) -> CookieHeader:
    """Validate a complete request header or a single account cookie, without echoing it."""
    value = value.strip()
    if re.match(r"set-cookie\s*:", value, re.IGNORECASE):
        raise ValueError(
            "This is a Set-Cookie response header. Copy the Cookie request header from Network instead."
        )
    if value.startswith(("{", "[")):
        raise ValueError(
            "This looks like a cookie export. Paste the Cookie request header, not JSON or a Cookies table."
        )
    if re.match(r"(?:curl\b|fetch\s*\(|GET\s|POST\s)", value, re.IGNORECASE):
        raise ValueError(
            "Paste only the Cookie request header, not the full request or Copy as cURL command."
        )
    value = re.sub(r"^cookie[ \t]*:[ \t]*", "", value, count=1, flags=re.IGNORECASE)
    if not value or any(ord(char) < 32 or ord(char) > 126 for char in value):
        raise ValueError(
            "Paste a single Cookie request header line; remove other headers or Cookies table rows."
        )
    parts: dict[str, str] = {}
    attributes = {
        "path",
        "domain",
        "expires",
        "max-age",
        "samesite",
        "secure",
        "httponly",
        "partitioned",
        "priority",
    }
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, separator, raw = part.partition("=")
        name, raw = name.strip(), raw.strip()
        if name.lower() in attributes:
            raise ValueError(
                "Cookie attributes such as Path or HttpOnly belong to Set-Cookie. Copy the Cookie request header instead."
            )
        if not separator:
            raise ValueError(
                "Include the cookie name and value, for example bb_session=<your value>; a bare value is not enough."
            )
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
            raise ValueError(
                "Cookie names must use name=value pairs separated by semicolons. Copy the request header rather than a table."
            )
        content = (
            raw[1:-1]
            if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"')
            else raw
        )
        if not re.fullmatch(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*", content):
            raise ValueError(
                "A cookie value has unsupported characters. Copy the Cookie request header exactly; do not decode it."
            )
        if name in parts:
            raise ValueError(
                "The cookie header repeats a cookie name. Copy the header from one tracker page request."
            )
        parts[name] = raw
    session = parts.get("bb_session", "").strip('"')
    if not session:
        raise ValueError("bb_session is missing or empty.")
    if session.casefold() in {
        "...",
        "<your value>",
        "your-session-value",
        "your_value",
        "your_session_value",
    }:
        raise ValueError(
            "Replace the example with your actual bb_session value from the browser request."
        )
    return CookieHeader(
        "; ".join(f"{name}={raw}" for name, raw in parts.items()), len(parts)
    )


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
                  ON CONFLICT(source_id) DO UPDATE SET mode=excluded.mode, secret=excluded.secret, last_error=excluded.last_error,
                  last_request_error=NULL""",
        (source_id, config["mode"], secret, error),
    )


def public_auth(db, source_id: int) -> dict[str, Any]:
    row = db.execute(
        "SELECT mode, last_error, last_request_error FROM source_auth WHERE source_id=?",
        (source_id,),
    ).fetchone()
    return {
        "mode": row["mode"] if row else "none",
        "last_error": (row["last_error"] or row["last_request_error"]) if row else None,
    }


def save_auth(
    db,
    source_id: int,
    mode: str,
    username: str | None,
    password: str | None,
    cookie: str | None,
    browser_headers: dict[str, str] | None = None,
) -> None:
    if mode == "none":
        db.execute("DELETE FROM source_auth WHERE source_id=?", (source_id,))
        return
    row = db.execute(
        "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
    ).fetchone()
    # A complete replacement can recover from a lost key without decrypting old data.
    replacement = bool(username and password) if mode == "password" else bool(cookie)
    old = {}
    if (
        row
        and row["mode"] == mode
        and (not replacement or (mode == "cookie" and browser_headers is None))
    ):
        try:
            old = _read(row)
        except SourceAuthError:
            if not replacement:
                raise
    config: dict[str, Any] = {"mode": mode, "cookies": []}
    if mode == "password":
        if browser_headers is not None:
            raise ValueError(
                "Browser request headers are supported by browser-session login only."
            )
        config.update(
            username=username or old.get("username"),
            password=password or old.get("password"),
        )
        if not config["username"] or not config["password"]:
            raise ValueError("A username and password are required for automatic login")
    elif mode == "cookie":
        header = cookie or old.get("cookie")
        config["cookie"] = parse_cookie_header(header or "").header
        context = old.get("browser_headers", {})
        if browser_headers is not None:
            context = {**context, **browser_headers} if browser_headers else {}
        config["browser_headers"] = validate_browser_headers(context)
    else:
        raise ValueError("Unknown login mode")
    _write(db, source_id, config)


def save_request_headers(db, source_id: int, value: str, base_url: str) -> None:
    if value.strip():
        cookie, headers = extract_request_headers(value, base_url)
        save_auth(db, source_id, "cookie", None, None, cookie, headers)
        return
    row = db.execute(
        "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
    ).fetchone()
    if not row or row["mode"] != "cookie":
        raise ValueError("Request headers are required.")
    config = _read(row)
    parse_cookie_header(config.get("cookie", ""))
    if not config.get("browser_headers", {}).get("User-Agent"):
        raise ValueError(
            "Saved headers are missing User-Agent. Paste full request headers."
        )


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


class _LoginFormParser(HTMLParser):
    """Retain hidden fields only from the form that contains the account input."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}
        self._form: dict[str, str] | None = None
        self._login_form = False

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "form":
            self._form = {}
            self._login_form = False
        elif tag == "input" and self._form is not None:
            name = values.get("name")
            if name == "login_username":
                self._login_form = True
            if name and values.get("type", "").lower() == "hidden":
                self._form[name] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            if self._login_form:
                self.fields = self._form
            self._form = None


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
        browser_headers = validate_browser_headers(config.get("browser_headers", {}))
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

        def request(
            target: str, data: bytes | None = None, *, phase: str
        ) -> tuple[str, int]:
            pause = _next_request.get(source_id, 0) - time.monotonic()
            if pause > 0:
                time.sleep(pause)
            req = urllib.request.Request(
                target,
                data=data,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html",
                    "Accept-Encoding": "identity",
                    **browser_headers,
                    "Referer": target if data is not None else source["base_url"],
                    **(
                        {"Origin": source["base_url"].rstrip("/")}
                        if data is not None
                        else {}
                    ),
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
                raise SourceHTTPError(error.code, error.headers, phase) from error
            except urllib.error.URLError as error:
                raise RuntimeError("Could not reach the configured source") from error
            finally:
                _next_request[source_id] = (
                    time.monotonic() + source["current_delay_seconds"]
                )

        def login() -> None:
            login_url = urllib.parse.urljoin(
                source["base_url"].rstrip("/") + "/", "forum/login.php"
            )
            login_page, _ = request(login_url, phase="opening the login page")
            if _logged_in(login_page):
                return
            if re.search(r"cap_sid|cap_code_|/captcha/", login_page, re.I):
                raise SourceAuthError(
                    "Source requires a CAPTCHA. Log in in your browser and use Browser session cookie in Edit source."
                )
            form = _LoginFormParser()
            form.feed(login_page)
            fields = {
                **form.fields,
                "login_username": config["username"],
                "login_password": config["password"],
                "login": "Login",
            }
            try:
                body = urllib.parse.urlencode(
                    fields, encoding=adapter.get("response_charset", "utf-8")
                ).encode("ascii")
            except UnicodeEncodeError as error:
                raise SourceAuthError(
                    "Credentials use characters unsupported by this source. Use a browser session cookie."
                ) from error
            login_html, _ = request(login_url, body, phase="submitting the login form")
            if not _logged_in(login_html):
                raise SourceAuthError(
                    "Login was not confirmed or requires a CAPTCHA. Check the login in your browser, or use Browser session cookie."
                )

        try:
            if config["mode"] == "password" and not config.get("cookies"):
                # Establish the login form's session before requesting protected pages.
                login()
                html, status = request(
                    url, phase="loading the requested page after login"
                )
            else:
                html, status = request(url, phase="checking the saved session")
                if not _logged_in(html):
                    if config["mode"] == "cookie":
                        raise SourceAuthError(
                            "Browser session expired or was rejected. Log in in your browser and replace the Cookie header in Edit source."
                        )
                    login()
                    html, status = request(
                        url, phase="loading the requested page after login"
                    )
            if not _logged_in(html):
                raise SourceAuthError(
                    "Login did not grant source access. Use a fresh browser session cookie."
                )
        except SourceHTTPError as error:
            # Keep diagnostics across page reloads without converting transient HTTP
            # failures into cached credential failures or disabling paced retries.
            with database.connect() as db:
                db.execute(
                    "UPDATE source_auth SET last_request_error=? WHERE source_id=?",
                    (str(error), source_id),
                )
            raise
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
