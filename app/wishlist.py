from __future__ import annotations

import sqlite3

from .database import search_terms


def query_key(query: str) -> str:
    return " ".join(sorted(set(search_terms(query))))


def ensure_wish(db: sqlite3.Connection, query: str, kind: str = "unspecified") -> int:
    query = " ".join(query.split())
    key = query_key(query)
    if not key:
        raise ValueError("Enter at least one searchable word")
    db.execute(
        "INSERT INTO wishlist(query, query_key, kind) VALUES (?, ?, ?) ON CONFLICT(query_key) DO UPDATE SET kind=CASE WHEN wishlist.kind='unspecified' THEN excluded.kind ELSE wishlist.kind END",
        (query, key, kind),
    )
    return db.execute("SELECT id FROM wishlist WHERE query_key=?", (key,)).fetchone()[0]


def initialise_wishlist(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS wishlist (
          id INTEGER PRIMARY KEY,
          query TEXT NOT NULL,
          query_key TEXT NOT NULL UNIQUE,
          kind TEXT NOT NULL DEFAULT 'unspecified' CHECK(kind IN ('movie', 'series', 'unspecified')),
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'archived')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          archived_at TEXT,
          downloaded_result_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS wishlist_results (
          wishlist_id INTEGER NOT NULL REFERENCES wishlist(id),
          result_id INTEGER NOT NULL REFERENCES results(id),
          PRIMARY KEY(wishlist_id, result_id)
        );
        CREATE INDEX IF NOT EXISTS wishlist_results_result ON wishlist_results(result_id);
    """)
    columns = {row["name"] for row in db.execute("PRAGMA table_info(crawl_jobs)")}
    if "wishlist_id" in columns:
        return
    db.execute(
        "ALTER TABLE crawl_jobs ADD COLUMN wishlist_id INTEGER REFERENCES wishlist(id)"
    )
    # One-time, idempotent upgrade of existing search history, including empty crawls.
    for job in db.execute("SELECT id, query FROM crawl_jobs").fetchall():
        if query_key(job["query"]):
            wish_id = ensure_wish(db, job["query"])
            db.execute(
                "UPDATE crawl_jobs SET wishlist_id=? WHERE id=?", (wish_id, job["id"])
            )
    for result in db.execute("SELECT id, remote_query FROM results").fetchall():
        if query_key(result["remote_query"]):
            wish_id = ensure_wish(db, result["remote_query"])
            link_result(db, wish_id, result["id"])


def link_result(db: sqlite3.Connection, wish_id: int, result_id: int) -> None:
    db.execute(
        "INSERT OR IGNORE INTO wishlist_results VALUES (?, ?)", (wish_id, result_id)
    )


def archive_download(db: sqlite3.Connection, result_id: int, query: str = "") -> None:
    # Crawl associations survive re-crawls and changes to results.remote_query.
    # The actual local query also covers wishes fulfilled by another crawl's result.
    result = db.execute("SELECT title FROM results WHERE id=?", (result_id,)).fetchone()
    if result:
        title_words = set(search_terms(result["title"]))
        for wish in db.execute(
            "SELECT id, query FROM wishlist WHERE status='active'"
        ).fetchall():
            if set(search_terms(wish["query"])).issubset(title_words):
                db.execute(
                    """UPDATE wishlist SET status='archived', archived_at=CURRENT_TIMESTAMP,
                             downloaded_result_id=? WHERE id=?""",
                    (result_id, wish["id"]),
                )
    db.execute(
        """UPDATE wishlist SET status='archived', archived_at=CURRENT_TIMESTAMP,
                  downloaded_result_id=? WHERE status='active' AND
                  (id IN (SELECT wishlist_id FROM wishlist_results WHERE result_id=?) OR query_key=?)""",
        (result_id, result_id, query_key(query)),
    )
