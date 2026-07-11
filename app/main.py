from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .adapters import AdapterError, get_adapter, get_adapter_definition, public_adapters, save_adapter
from .crawler import PacingRequiredError, fetch_magnet_now, run_one_job
from .database import connect, initialise

STATIC_DIR = Path(__file__).parent / "static"
WORD = re.compile(r"[\w]+", re.UNICODE)
USERNAME = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")
SESSION_COOKIE = "torrent_sniffer_session"
SESSION_DAYS = 14


class SourceInput(BaseModel):
    base_url: str
    kind: str
    min_delay_seconds: int = Field(default=20, ge=1, le=3600)


class SearchJobInput(BaseModel):
    source_id: int
    query: str = Field(min_length=1, max_length=180)


class AdapterInput(BaseModel):
    definition: dict[str, Any]


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=8, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


def _validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME.fullmatch(username):
        raise HTTPException(422, "Username must be 3-32 characters: letters, numbers, dot, underscore, or hyphen")
    return username


def _new_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16).hex()
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210_000).hex()
    return salt, password_hash


def _verify_password(password: str, salt: str, password_hash: str) -> bool:
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210_000).hex()
    return hmac.compare_digest(candidate, password_hash)


def _public_user(row: dict[str, Any]) -> dict[str, Any]:
    return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"])}


def _start_session(db, user: dict[str, Any], response: Response) -> None:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.now(UTC) + timedelta(days=SESSION_DAYS)).isoformat().replace("+00:00", "Z")
    db.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(UTC).isoformat().replace("+00:00", "Z"),))
    db.execute("INSERT INTO sessions(user_id, token_hash, expires_at) VALUES (?, ?, ?)", (user["id"], token_hash, expires_at))
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax")


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


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


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
        db.execute("INSERT INTO users(username, password_salt, password_hash, is_admin) VALUES (?, ?, ?, 1)", (username, salt, password_hash))
        user = dict(db.execute("SELECT * FROM users WHERE id=last_insert_rowid()").fetchone())
        _start_session(db, user, response)
    return _public_user(user)


@app.post("/api/auth/login")
def login(credentials: Credentials, response: Response):
    username = _validate_username(credentials.username)
    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        if not user or not _verify_password(credentials.password, user["password_salt"], user["password_hash"]):
            raise HTTPException(401, "Invalid username or password")
        user_data = dict(user)
        _start_session(db, user_data, response)
    return _public_user(user_data)


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie(SESSION_COOKIE)
    response.status_code = 204
    return response


@app.get("/api/auth/users")
def list_users(_: dict[str, Any] = Depends(require_admin)):
    with connect() as db:
        rows = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY username COLLATE NOCASE").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/auth/users", status_code=201)
def create_user(credentials: Credentials, _: dict[str, Any] = Depends(require_admin)):
    username = _validate_username(credentials.username)
    with connect() as db:
        if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone():
            raise HTTPException(409, "That username already exists")
        salt, password_hash = _new_password(credentials.password)
        db.execute("INSERT INTO users(username, password_salt, password_hash) VALUES (?, ?, ?)", (username, salt, password_hash))
        user = dict(db.execute("SELECT * FROM users WHERE id=last_insert_rowid()").fetchone())
    return _public_user(user)


@app.post("/api/auth/password", status_code=204)
def change_password(change: PasswordChange, user: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        account = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not account or not _verify_password(change.current_password, account["password_salt"], account["password_hash"]):
            raise HTTPException(401, "Current password is incorrect")
        salt, password_hash = _new_password(change.new_password)
        db.execute("UPDATE users SET password_salt=?, password_hash=? WHERE id=?", (salt, password_hash, user["id"]))
    return Response(status_code=204)


@app.get("/api/sources")
def list_sources(_: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM sources ORDER BY id DESC")]


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
def update_adapter(adapter_id: str, adapter: AdapterInput, _: dict[str, Any] = Depends(require_admin)):
    try:
        get_adapter(adapter_id)
        return save_adapter(adapter.definition, existing_id=adapter_id)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error


@app.post("/api/sources", status_code=201)
def create_source(source: SourceInput, _: dict[str, Any] = Depends(require_user)):
    parsed = urlparse(source.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, "base_url must be an absolute HTTP(S) URL")
    try:
        get_adapter(source.kind)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error
    base_url = source.base_url.rstrip("/")
    with connect() as db:
        db.execute(
            """INSERT INTO sources(base_url, kind, min_delay_seconds, current_delay_seconds) VALUES (?, ?, ?, ?)
               ON CONFLICT(base_url) DO UPDATE SET
                 kind=excluded.kind,
                 min_delay_seconds=excluded.min_delay_seconds,
                 current_delay_seconds=MAX(sources.current_delay_seconds, excluded.min_delay_seconds)""",
            (base_url, source.kind, source.min_delay_seconds, source.min_delay_seconds),
        )
        row = db.execute("SELECT * FROM sources WHERE base_url=?", (base_url,)).fetchone()
    return dict(row)


@app.put("/api/sources/{source_id}")
def update_source(source_id: int, source: SourceInput, _: dict[str, Any] = Depends(require_user)):
    parsed = urlparse(source.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, "Provide an absolute HTTP(S) URL")
    try:
        get_adapter(source.kind)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error
    with connect() as db:
        if not db.execute("SELECT 1 FROM sources WHERE id=?", (source_id,)).fetchone():
            raise HTTPException(404, "Source not found")
        db.execute(
            """UPDATE sources SET base_url=?, kind=?, min_delay_seconds=?,
               current_delay_seconds=MAX(current_delay_seconds, ?) WHERE id=?""",
            (source.base_url.rstrip("/"), source.kind, source.min_delay_seconds, source.min_delay_seconds, source_id),
        )
        return dict(db.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone())


@app.delete("/api/sources/{source_id}", status_code=204)
def delete_source(source_id: int, _: dict[str, Any] = Depends(require_user)) -> Response:
    with connect() as db:
        active = db.execute(
            "SELECT 1 FROM crawl_jobs WHERE source_id=? AND status IN ('queued', 'retrying', 'running')", (source_id,)
        ).fetchone()
        if active:
            raise HTTPException(409, "Stop running tasks before removing this source")
        jobs = [row["id"] for row in db.execute("SELECT id FROM crawl_jobs WHERE source_id=?", (source_id,))]
        if jobs:
            placeholders = ", ".join("?" for _ in jobs)
            db.execute(f"DELETE FROM request_log WHERE job_id IN ({placeholders})", jobs)
            db.execute(f"DELETE FROM detail_tasks WHERE job_id IN ({placeholders})", jobs)
            db.execute(f"DELETE FROM crawl_jobs WHERE id IN ({placeholders})", jobs)
        db.execute("DELETE FROM sources WHERE id=?", (source_id,))
    return Response(status_code=204)


@app.post("/api/jobs", status_code=201)
def queue_search(job: SearchJobInput, _: dict[str, Any] = Depends(require_user)):
    query = " ".join(job.query.split())
    with connect() as db:
        if not db.execute("SELECT 1 FROM sources WHERE id=?", (job.source_id,)).fetchone():
            raise HTTPException(404, "Source not found")
        db.execute("INSERT INTO crawl_jobs(source_id, query) VALUES (?, ?)", (job.source_id, query))
        row = db.execute("SELECT * FROM crawl_jobs WHERE id=last_insert_rowid()").fetchone()
    return dict(row)


@app.get("/api/jobs")
def list_jobs(_: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        rows = db.execute(
            """SELECT j.*, s.base_url, s.kind, s.current_delay_seconds,
               CASE WHEN j.status IN ('queued', 'retrying', 'running') THEN 'running'
                    WHEN j.status IN ('paused', 'stopped') THEN 'stopped' ELSE j.status END AS state,
               (SELECT COUNT(*) FROM detail_tasks d WHERE d.job_id=j.id AND d.on_demand=1 AND d.status IN ('queued', 'running', 'retrying')) AS pending_magnets
               FROM crawl_jobs j JOIN sources s ON s.id=j.source_id
               ORDER BY j.id DESC LIMIT 30"""
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/results/{result_id}/magnet")
def queue_magnet_lookup(result_id: int, _: dict[str, Any] = Depends(require_user)):
    try:
        magnet_link = fetch_magnet_now(result_id)
    except PacingRequiredError as error:
        raise HTTPException(429, str(error)) from error
    except ValueError as error:
        raise HTTPException(404, str(error)) from error
    except RuntimeError as error:
        raise HTTPException(502, str(error)) from error
    return {"magnet_link": magnet_link}


@app.get("/api/jobs/{job_id}/requests")
def job_requests(job_id: int, _: dict[str, Any] = Depends(require_user)):
    with connect() as db:
        if not db.execute("SELECT 1 FROM crawl_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Crawl not found")
        rows = db.execute("SELECT * FROM request_log WHERE job_id=? ORDER BY id DESC LIMIT 500", (job_id,)).fetchall()
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
            db.execute(f"UPDATE crawl_jobs SET status='queued', attempt_count=0, run_after=CURRENT_TIMESTAMP, last_error=NULL WHERE id=? AND status IN ({placeholders})", (job_id, *allowed))
        elif target == "complete":
            db.execute(f"UPDATE crawl_jobs SET status='complete', page_complete=1, completed_at=CURRENT_TIMESTAMP WHERE id=? AND status IN ({placeholders})", (job_id, *allowed))
        else:
            db.execute(f"UPDATE crawl_jobs SET status=? WHERE id=? AND status IN ({placeholders})", (target, job_id, *allowed))
        return dict(db.execute("SELECT * FROM crawl_jobs WHERE id=?", (job_id,)).fetchone())


@app.delete("/api/jobs/{job_id}", status_code=204)
def delete_job(job_id: int, _: dict[str, Any] = Depends(require_user)) -> Response:
    with connect() as db:
        job = db.execute("SELECT status FROM crawl_jobs WHERE id=?", (job_id,)).fetchone()
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
        row = db.execute(
            """SELECT
              (SELECT COUNT(*) FROM results) AS total_results,
              COUNT(*) AS total_crawls,
              SUM(status IN ('queued', 'running', 'retrying')) AS active_crawls,
              SUM(status = 'complete') AS completed_crawls
              FROM crawl_jobs"""
        ).fetchone()
    return dict(row)


@app.get("/api/results")
def search_results(q: str = "", include_description: bool = False, limit: int = 100, _: dict[str, Any] = Depends(require_user)):
    limit = max(1, min(limit, 250))
    words = WORD.findall(q.lower())
    with connect() as db:
        if not words:
            rows = db.execute("SELECT * FROM results ORDER BY discovered_at DESC LIMIT ?", (limit,)).fetchall()
        else:
            # Every token is mandatory. Field-scoping defaults this to title-only.
            field = "title" if not include_description else "{title description}"
            fts_query = " AND ".join(f'{field}:"{word.replace(chr(34), "")}"' for word in words)
            rows = db.execute(
                """SELECT r.* FROM results_fts f JOIN results r ON r.id=f.rowid
                   WHERE results_fts MATCH ? ORDER BY rank LIMIT ?""", (fts_query, limit)
            ).fetchall()
    return [dict(row) for row in rows]
