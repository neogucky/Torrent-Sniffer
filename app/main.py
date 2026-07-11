from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .adapters import AdapterError, get_adapter, get_adapter_definition, public_adapters, save_adapter
from .crawler import PacingRequiredError, fetch_magnet_now, run_one_job
from .database import connect, initialise

STATIC_DIR = Path(__file__).parent / "static"
WORD = re.compile(r"[\w]+", re.UNICODE)


class SourceInput(BaseModel):
    base_url: str
    kind: str
    min_delay_seconds: int = Field(default=20, ge=1, le=3600)


class SearchJobInput(BaseModel):
    source_id: int
    query: str = Field(min_length=1, max_length=180)


class AdapterInput(BaseModel):
    definition: dict[str, Any]


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


@app.get("/api/sources")
def list_sources():
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM sources ORDER BY id DESC")]


@app.get("/api/adapters")
def list_adapters():
    return public_adapters()


@app.get("/api/adapters/{adapter_id}")
def adapter_details(adapter_id: str):
    try:
        return get_adapter_definition(adapter_id)
    except AdapterError as error:
        raise HTTPException(404, str(error)) from error


@app.post("/api/adapters", status_code=201)
def create_adapter(adapter: AdapterInput):
    try:
        return save_adapter(adapter.definition)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error


@app.put("/api/adapters/{adapter_id}")
def update_adapter(adapter_id: str, adapter: AdapterInput):
    try:
        get_adapter(adapter_id)
        return save_adapter(adapter.definition, existing_id=adapter_id)
    except AdapterError as error:
        raise HTTPException(422, str(error)) from error


@app.post("/api/sources", status_code=201)
def create_source(source: SourceInput):
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
def update_source(source_id: int, source: SourceInput):
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
def delete_source(source_id: int) -> Response:
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
def queue_search(job: SearchJobInput):
    query = " ".join(job.query.split())
    with connect() as db:
        if not db.execute("SELECT 1 FROM sources WHERE id=?", (job.source_id,)).fetchone():
            raise HTTPException(404, "Source not found")
        db.execute("INSERT INTO crawl_jobs(source_id, query) VALUES (?, ?)", (job.source_id, query))
        row = db.execute("SELECT * FROM crawl_jobs WHERE id=last_insert_rowid()").fetchone()
    return dict(row)


@app.get("/api/jobs")
def list_jobs():
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
def queue_magnet_lookup(result_id: int):
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
def job_requests(job_id: int):
    with connect() as db:
        if not db.execute("SELECT 1 FROM crawl_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Crawl not found")
        rows = db.execute("SELECT * FROM request_log WHERE job_id=? ORDER BY id DESC LIMIT 500", (job_id,)).fetchall()
    return [dict(row) for row in rows]


@app.patch("/api/jobs/{job_id}")
def update_job(job_id: int, action: str):
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
def delete_job(job_id: int) -> Response:
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
def summary():
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
def search_results(q: str = "", include_description: bool = False, limit: int = 100):
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
