from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .adapters import (
    AdapterError,
    get_adapter,
    get_adapter_definition,
    public_adapters,
    save_adapter,
)
from .crawler import fetch_magnet_now, run_one_job
from .database import connect, initialise, search_terms
from .qbittorrent import (
    add_magnet as add_to_qbittorrent,
)
from .qbittorrent import (
    clear_config as clear_qbittorrent_config,
)
from .qbittorrent import (
    public_config as public_qbittorrent_config,
)
from .qbittorrent import (
    save_config as save_qbittorrent_config,
)
from .source_auth import fetch_source_html, public_auth, save_auth, source_lock
from .wishlist import archive_download, ensure_wish, query_key

STATIC_DIR = Path(__file__).parent / "static"
USERNAME = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")
SESSION_COOKIE = "torrent_sniffer_session"
SESSION_DAYS = 14


class SourceInput(BaseModel):
    base_url: str
    kind: str
    min_delay_seconds: int = Field(default=20, ge=1, le=3600)
    auth_mode: Literal["none", "password", "cookie"] | None = None
    auth_username: str | None = Field(default=None, max_length=256)
    auth_password: str | None = Field(default=None, max_length=1024, repr=False)
    auth_cookie: str | None = Field(default=None, max_length=16384, repr=False)


class SearchJobInput(BaseModel):
    source_id: int
    query: str = Field(min_length=1, max_length=180)


class AdapterInput(BaseModel):
    definition: dict[str, Any]


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=256)


class PasswordChange(BaseModel):
    new_password: str = Field(min_length=1, max_length=256)


class UserCreateInput(Credentials):
    group: str = "user"


class UserUpdateInput(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    group: str = "user"
    password: str | None = Field(default=None, max_length=256)


class QbittorrentLocation(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=1024)


class QbittorrentConfigInput(BaseModel):
    base_url: str
    api_key: str | None = Field(default=None, max_length=1024)
    locations: list[QbittorrentLocation] = Field(min_length=1)


class DownloadInput(BaseModel):
    query: str = Field(default="", max_length=180)


class WishInput(BaseModel):
    query: str = Field(min_length=1, max_length=180)
    kind: Literal["movie", "series", "unspecified"] = "unspecified"


class WishUpdate(BaseModel):
    status: Literal["active", "archived"]


class QbittorrentAddInput(DownloadInput):
    location_label: str = Field(min_length=1, max_length=80)


def _validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME.fullmatch(username):
        raise HTTPException(
            422,
            "Username must be 3-32 characters: letters, numbers, dot, underscore, or hyphen",
        )
    return username


def _new_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16).hex()
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 210_000
    ).hex()
    return salt, password_hash


def _verify_password(password: str, salt: str, password_hash: str) -> bool:
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 210_000
    ).hex()
    return hmac.compare_digest(candidate, password_hash)


def _public_user(row: dict[str, Any]) -> dict[str, Any]:
    is_admin = bool(row["is_admin"])
    return {
        "id": row["id"],
        "username": row["username"],
        "is_admin": is_admin,
        "group": "admin" if is_admin else "user",
    }


def _start_session(db, user: dict[str, Any], response: Response) -> None:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (
        (datetime.now(UTC) + timedelta(days=SESSION_DAYS))
        .isoformat()
        .replace("+00:00", "Z")
    )
    db.execute(
        "DELETE FROM sessions WHERE expires_at < ?",
        (datetime.now(UTC).isoformat().replace("+00:00", "Z"),),
    )
    db.execute(
        "INSERT INTO sessions(user_id, token_hash, expires_at) VALUES (?, ?, ?)",
        (user["id"], token_hash, expires_at),
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_DAYS * 86400,
        httponly=True,
        samesite="lax",
    )


def require_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Login required")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        row = db.execute(
            """SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
               WHERE s.token_hash=? AND s.expires_at>?""",
            (token_hash, datetime.now(UTC).isoformat().replace("+00:00", "Z")),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Your session has expired; please log in again")
    return _public_user(dict(row))


def require_admin(user: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    if not user["is_admin"]:
        raise HTTPException(403, "Administrator access required")
    return user


async def worker() -> None:
    while True:
        await asyncio.to_thread(run_one_job)
        await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialise()
    task = asyncio.create_task(worker())
    yield
    task.cancel()


app = FastAPI(title="Research Index", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def invalid_request(_: Request, error: RequestValidationError):
    # Pydantic error inputs may contain passwords or session cookies.
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": item["loc"], "msg": item["msg"], "type": item["type"]}
                for item in error.errors()
            ]
        },
        headers={"Cache-Control": "no-store"},
    )


@app.middleware("http")
async def prevent_auth_caching(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"}
    )


@app.get("/api/auth/status")
def auth_status(request: Request):
    with connect() as db:
        needs_setup = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    if needs_setup:
        return {"needs_setup": True, "user": None}
    try:
        user = require_user(request)
    except HTTPException:
        user = None
    return {"needs_setup": False, "user": user}


@app.post("/api/auth/setup", status_code=201)
def setup_owner(credentials: Credentials, response: Response):
    username = _validate_username(credentials.username)
    with connect() as db:
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise HTTPException(409, "An account already exists; use login instead")
        salt, password_hash = _new_password(credentials.password)
        try:
            db.execute(
                "INSERT INTO users(username, password_salt, password_hash, is_admin) VALUES (?, ?, ?, 1)",
                (username, salt, password_hash),
            )
        except sqlite3.IntegrityError as error:
            # Two setup submissions can race. Report the account-created state
            # instead of turning the second request into a server error.
            raise HTTPException(
                409, "An account already exists; use login instead"
            ) from error
        user = dict(
            db.execute("SELECT * FROM users WHERE id=last_insert_rowid()").fetchone()
        )
        _start_session(db, user, response)
    return _public_user(user)


@app.post("/api/auth/login")
def login(credentials: Credentials, response: Response):
    username = _validate_username(credentials.username)
    with connect() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone()
        if not user or not _verify_password(
            credentials.password, user["password_salt"], user["password_hash"]
        ):
            raise HTTPException(401, "Invalid username or password")
        user_data = dict(user)
        _start_session(db, user_data, response)
    return _public_user(user_data)


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE token_hash=?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            )
    response.delete_cookie(SESSION_COOKIE)
    response.status_code = 204
    return response


@app.get("/api/auth/users")
def list_users(_: dict[str, Any] = Depends(require_admin)):
    with connect() as db:
        rows = db.execute(
            "SELECT id, username, is_admin, created_at FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall()
    return [
        {**dict(row), "group": "admin" if row["is_admin"] else "user"} for row in rows
    ]


@app.post("/api/auth/users", status_code=201)
def create_user(
    credentials: UserCreateInput, _: dict[str, Any] = Depends(require_admin)
):
    username = _validate_username(credentials.username)
    if credentials.group not in {"admin", "user"}:
        raise HTTPException(422, "User group must be admin or user")
    with connect() as db:
        if db.execute(
            "SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone():
            raise HTTPException(409, "That username already exists")
        salt, password_hash = _new_password(credentials.password)
        db.execute(
            "INSERT INTO users(username, password_salt, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            (username, salt, password_hash, credentials.group == "admin"),
        )
        user = dict(
            db.execute("SELECT * FROM users WHERE id=last_insert_rowid()").fetchone()
        )
    return _public_user(user)


@app.put("/api/auth/users/{user_id}")
def update_user(
    user_id: int, update: UserUpdateInput, _: dict[str, Any] = Depends(require_admin)
):
    username = _validate_username(update.username)
    if update.group not in {"admin", "user"}:
        raise HTTPException(422, "User group must be admin or user")
    if update.password is not None and not update.password:
        raise HTTPException(422, "Password cannot be empty when changing it")
    with connect() as db:
        existing = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not existing:
            raise HTTPException(404, "User not found")
        if db.execute(
            "SELECT 1 FROM users WHERE username=? COLLATE NOCASE AND id<>?",
            (username, user_id),
        ).fetchone():
            raise HTTPException(409, "That username already exists")
        if existing["is_admin"] and update.group == "user":
            admin_count = db.execute(
                "SELECT COUNT(*) FROM users WHERE is_admin=1"
            ).fetchone()[0]
            if admin_count <= 1:
                raise HTTPException(409, "At least one administrator must remain")
        if update.password is not None:
            salt, password_hash = _new_password(update.password)
            db.execute(
                "UPDATE users SET username=?, is_admin=?, password_salt=?, password_hash=? WHERE id=?",
                (username, update.group == "admin", salt, password_hash, user_id),
            )
        else:
            db.execute(
                "UPDATE users SET username=?, is_admin=? WHERE id=?",
                (username, update.group == "admin", user_id),
            )
        user = dict(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())
    return _public_user(user)


@app.delete("/api/auth/users/{user_id}", status_code=204)
def delete_user(user_id: int, current_user: dict[str, Any] = Depends(require_admin)):
    if user_id == current_user["id"]:
        raise HTTPException(409, "You cannot remove your own account")
    with connect() as db:
        existing = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not existing:
            raise HTTPException(404, "User not found")
        if existing["is_admin"]:
            admin_count = db.execute(
                "SELECT COUNT(*) FROM users WHERE is_admin=1"
            ).fetchone()[0]
            if admin_count <= 1:
                raise HTTPException(409, "At least one administrator must remain")
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
    return Response(status_code=204)


@app.post("/api/auth/password", status_code=204)
def change_password(
    change: PasswordChange, user: dict[str, Any] = Depends(require_user)
):
    with connect() as db:
        salt, password_hash = _new_password(change.new_password)
        db.execute(
            "UPDATE users SET password_salt=?, password_hash=? WHERE id=?",
            (salt, password_hash, user["id"]),
        )
    return Response(status_code=204)


@app.get("/api/qbittorrent")
def qbittorrent_status(_: dict[str, Any] = Depends(require_user)):
    return public_qbittorrent_config()


@app.put("/api/qbittorrent", status_code=204)
def configure_qbittorrent(
    config: QbittorrentConfigInput, _: dict[str, Any] = Depends(require_admin)
):
    parsed = urlparse(config.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, "qBittorrent URL must be an absolute HTTP(S) URL")
    locations = [
        {"label": location.label.strip(), "path": location.path.strip()}
        for location in config.locations
    ]
    if any(not item["label"] or not item["path"] for item in locations):
        raise HTTPException(422, "Every file location needs a label and a path")
    if len({item["label"] for item in locations}) != len(locations):
        raise HTTPException(422, "File location labels must be unique")
    try:
        save_qbittorrent_config(config.base_url, config.api_key, locations)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    return Response(status_code=204)


@app.delete("/api/qbittorrent", status_code=204)
def remove_qbittorrent(_: dict[str, Any] = Depends(require_admin)):
    clear_qbittorrent_config()
    return Response(status_code=204)


@app.get("/api/sources")
def list_sources(_: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        return [
            _public_source(db, row)
            for row in db.execute("SELECT * FROM sources ORDER BY id DESC")
        ]


@app.get("/api/adapters")
def list_adapters(_: dict[str, Any] = Depends(require_user)):
    return public_adapters()


@app.get("/api/adapters/{adapter_id}")
def adapter_details(adapter_id: str, _: dict[str, Any] = Depends(require_admin)):
    try:
        return get_adapter_definition(adapter_id)
    except AdapterError as error:
        raise HTTPException(404, str(error)) from error


@app.post("/api/adapters", status_code=201)
def create_adapter(adapter: AdapterInput, _: dict[str, Any] = Depends(require_admin)):
    try:
        return save_adapter(adapter.definition)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error


@app.put("/api/adapters/{adapter_id}")
def update_adapter(
    adapter_id: str, adapter: AdapterInput, _: dict[str, Any] = Depends(require_admin)
):
    try:
        get_adapter(adapter_id)
        return save_adapter(adapter.definition, existing_id=adapter_id)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error


def _public_source(db, row):
    return {**dict(row), "auth": public_auth(db, row["id"])}


def _validate_source(source: SourceInput) -> str:
    parsed = urlparse(source.base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(
            422, "Provide an HTTP(S) source URL without credentials, query, or fragment"
        )
    if source.kind == "rutracker" and (
        parsed.scheme != "https" or parsed.path not in {"", "/"}
    ):
        raise HTTPException(
            422, "Account sources require an HTTPS site URL without a forum path"
        )
    if source.kind != "rutracker" and source.auth_mode not in {None, "none"}:
        raise HTTPException(422, "Account login is supported by the RuTracker adapter")
    try:
        get_adapter(source.kind)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error
    return source.base_url.rstrip("/")


def _save_source_auth(db, source_id: int, source: SourceInput, user):
    if source.auth_mode is None:
        return
    if not user["is_admin"]:
        raise HTTPException(403, "Only administrators may configure source logins")
    try:
        save_auth(
            db,
            source_id,
            source.auth_mode,
            source.auth_username,
            source.auth_password,
            source.auth_cookie,
        )
    except (ValueError, RuntimeError) as error:
        raise HTTPException(422, str(error)) from error


def _protect_source(db, source: SourceInput, user, existing=None):
    if (
        source.kind == "rutracker"
        or (
            existing
            and (
                existing["kind"] == "rutracker"
                or public_auth(db, existing["id"])["mode"] != "none"
            )
        )
    ) and not user["is_admin"]:
        raise HTTPException(403, "Only administrators may change account sources")


@app.post("/api/sources", status_code=201)
def create_source(source: SourceInput, user: dict[str, Any] = Depends(require_user)):
    base_url = _validate_source(source)
    with connect() as db:
        existing = db.execute(
            "SELECT * FROM sources WHERE base_url=?", (base_url,)
        ).fetchone()
        _protect_source(db, source, user, existing)
        if existing:
            raise HTTPException(409, "A source with this URL exists; edit it instead")
        source_id = db.execute(
            "INSERT INTO sources(base_url, kind, min_delay_seconds, current_delay_seconds) VALUES (?, ?, ?, ?)",
            (base_url, source.kind, source.min_delay_seconds, source.min_delay_seconds),
        ).lastrowid
        _save_source_auth(db, source_id, source, user)
        return _public_source(
            db, db.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
        )


@app.put("/api/sources/{source_id}")
def update_source(
    source_id: int, source: SourceInput, user: dict[str, Any] = Depends(require_user)
):
    base_url = _validate_source(source)
    with source_lock(source_id), connect() as db:
        existing = db.execute(
            "SELECT * FROM sources WHERE id=?", (source_id,)
        ).fetchone()
        if not existing:
            raise HTTPException(404, "Source not found")
        _protect_source(db, source, user, existing)
        changed_origin = (
            base_url != existing["base_url"] or source.kind != existing["kind"]
        )
        if changed_origin:
            db.execute("DELETE FROM source_auth WHERE source_id=?", (source_id,))
            # Old magnets may contain source-specific account data as well.
            db.execute(
                "UPDATE results SET magnet_link=NULL WHERE source_id=?", (source_id,)
            )
        try:
            db.execute(
                """UPDATE sources SET base_url=?, kind=?, min_delay_seconds=?,
                current_delay_seconds=MAX(current_delay_seconds, ?) WHERE id=?""",
                (
                    base_url,
                    source.kind,
                    source.min_delay_seconds,
                    source.min_delay_seconds,
                    source_id,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise HTTPException(409, "A source with this URL already exists") from error
        _save_source_auth(db, source_id, source, user)
        return _public_source(
            db, db.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
        )


@app.post("/api/sources/{source_id}/login")
def test_source_login(source_id: int, _: dict[str, Any] = Depends(require_admin)):
    with source_lock(source_id):
        with connect() as db:
            source = db.execute(
                "SELECT * FROM sources WHERE id=?", (source_id,)
            ).fetchone()
            if not source:
                raise HTTPException(404, "Source not found")
            if source["kind"] != "rutracker":
                raise HTTPException(422, "This source does not use account login")
            db.execute(
                "UPDATE source_auth SET last_error=NULL WHERE source_id=?", (source_id,)
            )
        try:
            fetch_source_html(
                source_id,
                source["base_url"].rstrip("/") + "/forum/tracker.php",
                get_adapter(source["kind"]),
            )
        except RuntimeError as error:
            raise HTTPException(502, str(error)) from error
    return {"authenticated": True}


@app.delete("/api/sources/{source_id}", status_code=204)
def delete_source(
    source_id: int, user: dict[str, Any] = Depends(require_user)
) -> Response:
    with source_lock(source_id), connect() as db:
        existing = db.execute(
            "SELECT * FROM sources WHERE id=?", (source_id,)
        ).fetchone()
        if not existing:
            raise HTTPException(404, "Source not found")
        _protect_source(
            db,
            SourceInput(base_url=existing["base_url"], kind=existing["kind"]),
            user,
            existing,
        )
        active = db.execute(
            "SELECT 1 FROM crawl_jobs WHERE source_id=? AND status IN ('queued', 'retrying', 'running')",
            (source_id,),
        ).fetchone()
        if active:
            raise HTTPException(409, "Stop running tasks before removing this source")
        jobs = [
            row["id"]
            for row in db.execute(
                "SELECT id FROM crawl_jobs WHERE source_id=?", (source_id,)
            )
        ]
        if jobs:
            placeholders = ", ".join("?" for _ in jobs)
            db.execute(
                f"DELETE FROM request_log WHERE job_id IN ({placeholders})", jobs
            )
            db.execute(
                f"DELETE FROM detail_tasks WHERE job_id IN ({placeholders})", jobs
            )
            db.execute(f"DELETE FROM crawl_jobs WHERE id IN ({placeholders})", jobs)
        db.execute("DELETE FROM source_auth WHERE source_id=?", (source_id,))
        db.execute("DELETE FROM sources WHERE id=?", (source_id,))
    return Response(status_code=204)


@app.post("/api/jobs", status_code=201)
def queue_search(job: SearchJobInput, _: dict[str, Any] = Depends(require_user)):
    query = " ".join(job.query.split())
    if not query_key(query):
        raise HTTPException(422, "Enter at least one searchable word")
    with connect() as db:
        source = db.execute(
            "SELECT kind FROM sources WHERE id=?", (job.source_id,)
        ).fetchone()
        if not source:
            raise HTTPException(404, "Source not found")
        try:
            query.encode(get_adapter(source["kind"])["search"].get("charset", "utf-8"))
        except UnicodeEncodeError as error:
            raise HTTPException(
                422, "The search term contains characters unsupported by this source"
            ) from error
        wish_id = ensure_wish(db, query)
        db.execute(
            "INSERT INTO crawl_jobs(source_id, query, wishlist_id) VALUES (?, ?, ?)",
            (job.source_id, query, wish_id),
        )
        row = db.execute(
            "SELECT * FROM crawl_jobs WHERE id=last_insert_rowid()"
        ).fetchone()
    return dict(row)


@app.get("/api/jobs")
def list_jobs(_: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        rows = db.execute("""SELECT j.*, s.base_url, s.kind, s.current_delay_seconds,
               CASE WHEN j.status IN ('queued', 'retrying', 'running') THEN 'running'
                    WHEN j.status IN ('paused', 'stopped') THEN 'stopped' ELSE j.status END AS state,
               (SELECT COUNT(*) FROM detail_tasks d WHERE d.job_id=j.id AND d.on_demand=1 AND d.status IN ('queued', 'running', 'retrying')) AS pending_magnets
               FROM crawl_jobs j JOIN sources s ON s.id=j.source_id
               ORDER BY j.id DESC LIMIT 30""").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/results/{result_id}/magnet")
def queue_magnet_lookup(result_id: int, _: dict[str, Any] = Depends(require_user)):
    try:
        magnet_link = fetch_magnet_now(result_id)
    except ValueError as error:
        raise HTTPException(404, str(error)) from error
    except RuntimeError as error:
        raise HTTPException(502, str(error)) from error
    return {"magnet_link": magnet_link}


@app.post("/api/results/{result_id}/qbittorrent", status_code=204)
def add_result_to_qbittorrent(
    result_id: int,
    request: QbittorrentAddInput,
    _: dict[str, Any] = Depends(require_user),
):
    with connect() as db:
        result = db.execute(
            "SELECT magnet_link FROM results WHERE id=?", (result_id,)
        ).fetchone()
    if not result:
        raise HTTPException(404, "Result not found")
    magnet_link = result["magnet_link"]
    if not magnet_link:
        try:
            magnet_link = fetch_magnet_now(result_id)
        except ValueError as error:
            raise HTTPException(404, str(error)) from error
        except RuntimeError as error:
            raise HTTPException(502, str(error)) from error
    if not magnet_link:
        raise HTTPException(422, "The detail page did not contain a magnet link")
    try:
        add_to_qbittorrent(magnet_link, request.location_label)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
    except RuntimeError as error:
        raise HTTPException(502, str(error)) from error
    with connect() as db:
        archive_download(db, result_id, request.query)
    return Response(status_code=204)


@app.post("/api/results/{result_id}/downloaded", status_code=204)
def external_download(
    result_id: int, request: DownloadInput, _: dict[str, Any] = Depends(require_user)
):
    with connect() as db:
        result = db.execute(
            "SELECT magnet_link FROM results WHERE id=?", (result_id,)
        ).fetchone()
        if not result:
            raise HTTPException(404, "Result not found")
        if not result["magnet_link"]:
            raise HTTPException(
                409, "Fetch a magnet link before starting an external download"
            )
        archive_download(db, result_id, request.query)
    return Response(status_code=204)


@app.get("/api/wishlist")
def list_wishlist(
    state: Literal["active", "archived"] = "active",
    _: dict[str, Any] = Depends(require_user),
):
    with connect() as db:
        return [
            dict(row)
            for row in db.execute(
                """SELECT w.*,
            (SELECT COUNT(*) FROM wishlist_results wr JOIN results r ON r.id=wr.result_id WHERE wr.wishlist_id=w.id) AS result_count,
            (SELECT COUNT(*) FROM crawl_jobs j WHERE j.wishlist_id=w.id) AS crawl_count,
            (SELECT COUNT(*) FROM crawl_jobs j WHERE j.wishlist_id=w.id AND j.status IN ('queued', 'retrying', 'running')) AS active_crawls,
            (SELECT MAX(j.completed_at) FROM crawl_jobs j WHERE j.wishlist_id=w.id AND j.status='complete') AS last_crawled_at
            FROM wishlist w WHERE w.status=? ORDER BY w.created_at DESC, w.id DESC""",
                (state,),
            )
        ]


@app.post("/api/wishlist", status_code=201)
def add_wish(wish: WishInput, _: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        try:
            wish_id = ensure_wish(db, wish.query, wish.kind)
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        return dict(
            db.execute("SELECT * FROM wishlist WHERE id=?", (wish_id,)).fetchone()
        )


@app.patch("/api/wishlist/{wish_id}")
def update_wish(
    wish_id: int, wish: WishUpdate, _: dict[str, Any] = Depends(require_user)
):
    with connect() as db:
        if not db.execute("SELECT 1 FROM wishlist WHERE id=?", (wish_id,)).fetchone():
            raise HTTPException(404, "Wishlist entry not found")
        db.execute(
            """UPDATE wishlist SET status=?, archived_at=CASE WHEN ?='archived' THEN CURRENT_TIMESTAMP ELSE NULL END,
            downloaded_result_id=NULL WHERE id=?""",
            (wish.status, wish.status, wish_id),
        )
        return dict(
            db.execute("SELECT * FROM wishlist WHERE id=?", (wish_id,)).fetchone()
        )


@app.delete("/api/wishlist/{wish_id}", status_code=204)
def delete_wish(wish_id: int, _: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        active = db.execute(
            "SELECT 1 FROM crawl_jobs WHERE wishlist_id=? AND status IN ('queued', 'retrying', 'running')",
            (wish_id,),
        ).fetchone()
        if active:
            raise HTTPException(409, "Stop active crawls before removing this entry")
        db.execute(
            "UPDATE crawl_jobs SET wishlist_id=NULL WHERE wishlist_id=?", (wish_id,)
        )
        db.execute("DELETE FROM wishlist_results WHERE wishlist_id=?", (wish_id,))
        db.execute("DELETE FROM wishlist WHERE id=?", (wish_id,))
    return Response(status_code=204)


@app.get("/api/jobs/{job_id}/requests")
def job_requests(job_id: int, _: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        if not db.execute("SELECT 1 FROM crawl_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Crawl not found")
        rows = db.execute(
            "SELECT * FROM request_log WHERE job_id=? ORDER BY id DESC LIMIT 500",
            (job_id,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.patch("/api/jobs/{job_id}")
def update_job(job_id: int, action: str, _: dict[str, Any] = Depends(require_user)):
    actions = {
        "stop": (("queued", "retrying", "running", "paused"), "stopped"),
        "continue": (("stopped",), "queued"),
        "retry": (("failed",), "queued"),
        "complete": (("stopped", "failed", "paused"), "complete"),
    }
    if action not in actions:
        raise HTTPException(422, "action must be stop, continue, retry, or complete")
    allowed, target = actions[action]
    placeholders = ", ".join("?" for _ in allowed)
    with connect() as db:
        job = db.execute("SELECT * FROM crawl_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(404, "Crawl not found")
        if job["status"] not in allowed:
            raise HTTPException(409, f"Cannot {action} a {job['status']} crawl")
        if target == "queued":
            db.execute(
                f"UPDATE crawl_jobs SET status='queued', attempt_count=0, run_after=CURRENT_TIMESTAMP, last_error=NULL WHERE id=? AND status IN ({placeholders})",
                (job_id, *allowed),
            )
        elif target == "complete":
            db.execute(
                f"UPDATE crawl_jobs SET status='complete', page_complete=1, completed_at=CURRENT_TIMESTAMP WHERE id=? AND status IN ({placeholders})",
                (job_id, *allowed),
            )
        else:
            db.execute(
                f"UPDATE crawl_jobs SET status=? WHERE id=? AND status IN ({placeholders})",
                (target, job_id, *allowed),
            )
        return dict(
            db.execute("SELECT * FROM crawl_jobs WHERE id=?", (job_id,)).fetchone()
        )


@app.delete("/api/jobs/{job_id}", status_code=204)
def delete_job(job_id: int, _: dict[str, Any] = Depends(require_user)) -> Response:
    with connect() as db:
        job = db.execute(
            "SELECT status FROM crawl_jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not job:
            raise HTTPException(404, "Task not found")
        if job["status"] in {"queued", "retrying", "running"}:
            raise HTTPException(409, "Stop a running task before removing it")
        db.execute("DELETE FROM request_log WHERE job_id=?", (job_id,))
        db.execute("DELETE FROM detail_tasks WHERE job_id=?", (job_id,))
        db.execute("DELETE FROM crawl_jobs WHERE id=?", (job_id,))
    return Response(status_code=204)


@app.get("/api/summary")
def summary(_: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        row = db.execute("""SELECT
              (SELECT COUNT(*) FROM results) AS total_results,
              COUNT(*) AS total_crawls,
              COALESCE(SUM(CASE WHEN status IN ('queued', 'running', 'retrying') THEN 1 ELSE 0 END), 0) AS active_crawls,
              COALESCE(SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END), 0) AS completed_crawls
              FROM crawl_jobs""").fetchone()
    return dict(row)


@app.get("/api/results")
def search_results(
    q: str = "",
    wishlist_id: int | None = None,
    match_mode: str = "all",
    min_size_bytes: int = 0,
    max_size_bytes: int | None = None,
    min_seeders: int = 0,
    sort: str = "discovered_desc",
    limit: int = 100,
    exclude: list[str] = Query(default=[]),
    _: dict[str, Any] = Depends(require_user),
):
    limit = max(1, min(limit, 250))
    if min_size_bytes < 0 or (max_size_bytes is not None and max_size_bytes < 0):
        raise HTTPException(422, "Size filters cannot be negative")
    if max_size_bytes is not None and max_size_bytes < min_size_bytes:
        raise HTTPException(422, "Maximum size must be at least the minimum size")
    if min_seeders < 0:
        raise HTTPException(422, "Minimum seeders cannot be negative")
    if match_mode not in {"all", "any", "ordered"}:
        raise HTTPException(422, "Match mode must be all, any, or ordered")
    words = search_terms(q)
    ordering = {
        "discovered_desc": "r.discovered_at DESC",
        "size_desc": "r.size_bytes IS NULL, r.size_bytes DESC, r.discovered_at DESC",
        "size_asc": "r.size_bytes IS NULL, r.size_bytes ASC, r.discovered_at DESC",
        "seeders_desc": "r.seeders IS NULL, r.seeders DESC, r.discovered_at DESC",
        "seeders_asc": "r.seeders IS NULL, r.seeders ASC, r.discovered_at DESC",
        "created_desc": "r.torrent_created_at IS NULL, r.torrent_created_at DESC, r.discovered_at DESC",
        "created_asc": "r.torrent_created_at IS NULL, r.torrent_created_at ASC, r.discovered_at DESC",
    }
    if sort not in ordering:
        raise HTTPException(422, "Unknown result sort")
    filters: list[str] = []
    params: list[Any] = []
    if wishlist_id is not None:
        filters.append(
            "r.id IN (SELECT result_id FROM wishlist_results WHERE wishlist_id=?)"
        )
        params.append(wishlist_id)
    excluded_terms = list(
        dict.fromkeys(term for value in exclude[:50] for term in search_terms(value))
    )
    for term in excluded_terms:
        filters.append(
            "search_contains(COALESCE(r.title, '') || ' ' || COALESCE(r.category, ''), ?) = 0"
        )
        params.append(term)
    if min_size_bytes:
        filters.append("r.size_bytes >= ?")
        params.append(min_size_bytes)
    if max_size_bytes is not None:
        filters.append("r.size_bytes < ?")
        params.append(max_size_bytes)
    if min_seeders:
        filters.append("COALESCE(r.seeders, 0) >= ?")
        params.append(min_seeders)
    with connect() as db:
        where_clauses: list[str] = []
        if not words:
            sql = "SELECT r.* FROM results r"
        else:
            sql = "SELECT r.* FROM results r"
            if match_mode == "all":
                conditions = ["search_contains(r.title, ?) = 1" for _ in words]
                where_clauses.append("(" + " AND ".join(conditions) + ")")
                params = [*words, *params]
            elif match_mode == "any":
                conditions = ["search_contains(r.title, ?) = 1" for _ in words]
                where_clauses.append("(" + " OR ".join(conditions) + ")")
                params = [*words, *params]
            else:
                where_clauses.append("search_in_order(r.title, ?) = 1")
                params = [q, *params]
        if filters:
            where_clauses.extend(filters)
        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)
        sql += f" ORDER BY {ordering[sort]} LIMIT ?"
        rows = db.execute(sql, (*params, limit)).fetchall()
    return [dict(row) for row in rows]
