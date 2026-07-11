from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DB_PATH = Path(os.getenv("RESEARCH_INDEX_DB", "data/research-index.sqlite"))


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialise() -> None:
    from .adapters import ensure_default_adapter
    ensure_default_adapter()
    with connect() as db:
        db.executescript(
            """
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS sources (
              id INTEGER PRIMARY KEY,
              base_url TEXT NOT NULL UNIQUE,
              kind TEXT NOT NULL DEFAULT 'unconfigured',
              min_delay_seconds INTEGER NOT NULL DEFAULT 20 CHECK(min_delay_seconds >= 1),
              current_delay_seconds INTEGER NOT NULL DEFAULT 20,
              successful_requests INTEGER NOT NULL DEFAULT 0,
              next_allowed_at TEXT,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS crawl_jobs (
              id INTEGER PRIMARY KEY,
              source_id INTEGER NOT NULL REFERENCES sources(id),
              query TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'retrying', 'paused', 'stopped', 'complete', 'failed')),
              attempt_count INTEGER NOT NULL DEFAULT 0,
              run_after TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              last_error TEXT,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              completed_at TEXT,
              next_page INTEGER NOT NULL DEFAULT 1,
              pages_crawled INTEGER NOT NULL DEFAULT 0,
              results_found INTEGER NOT NULL DEFAULT 0,
              matches_seen INTEGER NOT NULL DEFAULT 0,
              page_complete INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS results (
              id INTEGER PRIMARY KEY,
              source_id INTEGER NOT NULL REFERENCES sources(id),
              remote_query TEXT NOT NULL,
              title TEXT NOT NULL,
              category TEXT,
              details_url TEXT NOT NULL,
              size TEXT,
              size_bytes INTEGER,
              seeders INTEGER,
              leechers INTEGER,
              uploader TEXT,
              torrent_created_at TEXT,
              description TEXT NOT NULL DEFAULT '',
              magnet_link TEXT,
              discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(source_id, details_url)
            );

            CREATE TABLE IF NOT EXISTS detail_tasks (
              id INTEGER PRIMARY KEY,
              job_id INTEGER NOT NULL REFERENCES crawl_jobs(id),
              result_id INTEGER NOT NULL REFERENCES results(id),
              source_id INTEGER NOT NULL REFERENCES sources(id),
              details_url TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'retrying', 'complete', 'failed')),
              attempt_count INTEGER NOT NULL DEFAULT 0,
              run_after TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              last_error TEXT,
              on_demand INTEGER NOT NULL DEFAULT 0,
              UNIQUE(job_id, result_id)
            );
            CREATE INDEX IF NOT EXISTS detail_tasks_ready ON detail_tasks(status, run_after);

            CREATE TABLE IF NOT EXISTS request_log (
              id INTEGER PRIMARY KEY,
              source_id INTEGER NOT NULL REFERENCES sources(id),
              job_id INTEGER NOT NULL REFERENCES crawl_jobs(id),
              detail_task_id INTEGER REFERENCES detail_tasks(id),
              request_type TEXT NOT NULL CHECK(request_type IN ('search', 'detail')),
              url TEXT NOT NULL,
              page INTEGER,
              status TEXT NOT NULL CHECK(status IN ('succeeded', 'failed')),
              http_status INTEGER,
              result_count INTEGER,
              wait_before_seconds INTEGER NOT NULL,
              wait_adjustment_seconds INTEGER NOT NULL DEFAULT 0,
              effective_wait_seconds INTEGER NOT NULL,
              error TEXT,
              requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS request_log_job ON request_log(job_id, id DESC);

            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY,
              username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_salt TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              is_admin INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
              id INTEGER PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id),
              token_hash TEXT NOT NULL UNIQUE,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS sessions_token ON sessions(token_hash);

            CREATE TABLE IF NOT EXISTS qbittorrent_config (
              id INTEGER PRIMARY KEY CHECK(id=1),
              base_url TEXT NOT NULL,
              api_key TEXT NOT NULL,
              locations_json TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS results_fts USING fts5(
              title, description, content='results', content_rowid='id', tokenize='unicode61 remove_diacritics 2'
            );
            CREATE TRIGGER IF NOT EXISTS results_insert AFTER INSERT ON results BEGIN
              INSERT INTO results_fts(rowid, title, description) VALUES (new.id, new.title, new.description);
            END;
            CREATE TRIGGER IF NOT EXISTS results_delete AFTER DELETE ON results BEGIN
              INSERT INTO results_fts(results_fts, rowid, title, description) VALUES ('delete', old.id, old.title, old.description);
            END;
            CREATE TRIGGER IF NOT EXISTS results_update AFTER UPDATE OF title, description ON results BEGIN
              INSERT INTO results_fts(results_fts, rowid, title, description) VALUES ('delete', old.id, old.title, old.description);
              INSERT INTO results_fts(rowid, title, description) VALUES (new.id, new.title, new.description);
            END;
            """
        )
        _migrate_crawl_jobs(db)
        _migrate_additive_columns(db)
        _backfill_result_sizes(db)
        _backfill_legacy_progress(db)
        db.execute("CREATE INDEX IF NOT EXISTS crawl_jobs_ready ON crawl_jobs(status, run_after)")
        db.execute("CREATE INDEX IF NOT EXISTS results_size_bytes ON results(size_bytes)")
        db.execute("CREATE INDEX IF NOT EXISTS results_seeders ON results(seeders)")
        db.execute("CREATE INDEX IF NOT EXISTS results_torrent_created_at ON results(torrent_created_at)")


def _migrate_crawl_jobs(db: sqlite3.Connection) -> None:
    """Upgrade databases made by the first single-page prototype without losing data."""
    definition = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='crawl_jobs'"
    ).fetchone()[0]
    if "'paused'" in definition and "next_page" in definition:
        return
    db.execute("DROP INDEX IF EXISTS crawl_jobs_ready")
    db.execute("ALTER TABLE crawl_jobs RENAME TO crawl_jobs_legacy")
    db.execute(
        """CREATE TABLE crawl_jobs (
          id INTEGER PRIMARY KEY,
          source_id INTEGER NOT NULL REFERENCES sources(id),
          query TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'retrying', 'paused', 'stopped', 'complete', 'failed')),
          attempt_count INTEGER NOT NULL DEFAULT 0,
          run_after TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          last_error TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          completed_at TEXT,
          next_page INTEGER NOT NULL DEFAULT 1,
          pages_crawled INTEGER NOT NULL DEFAULT 0,
          results_found INTEGER NOT NULL DEFAULT 0
        )"""
    )
    db.execute(
        """INSERT INTO crawl_jobs(id, source_id, query, status, attempt_count, run_after, last_error, created_at, completed_at)
           SELECT id, source_id, query, status, attempt_count, run_after, last_error, created_at, completed_at
           FROM crawl_jobs_legacy"""
    )
    db.execute("DROP TABLE crawl_jobs_legacy")


def _backfill_legacy_progress(db: sqlite3.Connection) -> None:
    """Give completed searches created before pagination useful initial progress values."""
    db.execute("UPDATE crawl_jobs SET pages_crawled=1 WHERE status='complete' AND pages_crawled=0")
    db.execute(
        """UPDATE crawl_jobs AS job SET results_found=(
             SELECT COUNT(*) FROM results
             WHERE source_id=job.source_id AND remote_query=job.query
           )
           WHERE status='complete' AND results_found=0"""
    )
    db.execute("UPDATE crawl_jobs SET page_complete=1 WHERE status='complete'")


def _migrate_additive_columns(db: sqlite3.Connection) -> None:
    """Add non-breaking fields to databases created before adaptive pacing."""
    if _add_column_if_missing(db, "sources", "current_delay_seconds", "INTEGER NOT NULL DEFAULT 20"):
        db.execute("UPDATE sources SET current_delay_seconds=min_delay_seconds")
    _add_column_if_missing(db, "sources", "successful_requests", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "sources", "kind", "TEXT NOT NULL DEFAULT 'unconfigured'")
    # If exactly one adapter exists, preserve legacy sources by assigning it generically.
    from .adapters import load_adapters
    available = load_adapters()
    if len(available) == 1:
        adapter_id = next(iter(available))
        db.execute("UPDATE sources SET kind=? WHERE kind<>?", (adapter_id, adapter_id))
    _add_column_if_missing(db, "crawl_jobs", "page_complete", "INTEGER NOT NULL DEFAULT 0")
    if _add_column_if_missing(db, "crawl_jobs", "matches_seen", "INTEGER NOT NULL DEFAULT 0"):
        db.execute("UPDATE crawl_jobs SET matches_seen=results_found")
    _add_column_if_missing(db, "results", "magnet_link", "TEXT")
    _add_column_if_missing(db, "results", "size_bytes", "INTEGER")
    _add_column_if_missing(db, "results", "torrent_created_at", "TEXT")
    _add_column_if_missing(db, "detail_tasks", "on_demand", "INTEGER NOT NULL DEFAULT 0")
    db.execute("UPDATE detail_tasks SET on_demand=0 WHERE on_demand=1")
    db.execute("UPDATE crawl_jobs SET status='stopped' WHERE status='paused'")


def _backfill_result_sizes(db: sqlite3.Connection) -> None:
    """Make stored size text from earlier crawls immediately filterable, locally."""
    factors = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    for row in db.execute("SELECT id, size FROM results WHERE size_bytes IS NULL AND size IS NOT NULL"):
        match = re.search(r"([0-9]+(?:[.,][0-9]+)?)\s*([KMGT]?i?B)", row["size"], flags=re.IGNORECASE)
        if not match:
            continue
        unit = match.group(2).upper().replace("I", "")
        if unit in factors:
            value = float(match.group(1).replace(",", "."))
            db.execute("UPDATE results SET size_bytes=? WHERE id=?", (round(value * factors[unit]), row["id"]))


def _add_column_if_missing(db: sqlite3.Connection, table: str, name: str, definition: str) -> bool:
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
    if name in columns:
        return False
    db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    return True
