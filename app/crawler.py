from __future__ import annotations

import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import unescape
from html.parser import HTMLParser
from typing import Any

from .adapters import get_adapter
from .database import connect

USER_AGENT = "ResearchIndex/0.1 (+local metadata research; contact: local-user)"
MAX_ATTEMPTS = 5


class PacingRequiredError(Exception):
    def __init__(self, seconds: int) -> None:
        self.seconds = seconds
        super().__init__(f"Source pacing requires waiting about {seconds} seconds before another request")


def build_search_url(adapter: dict[str, Any], base_url: str, query: str, page: int) -> str:
    search = adapter["search"]
    encoded_query = urllib.parse.quote(query, safe="") if search.get("query_encoding", "percent") == "percent" else query
    path = str(search["path_template"]).format(query=encoded_query, page=page)
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


@dataclass
class ParsedResult:
    title: str
    details_url: str
    category: str | None = None
    size: str | None = None
    seeders: int | None = None
    leechers: int | None = None
    uploader: str | None = None


class SearchTableParser(HTMLParser):
    """Collect generic HTML table rows, cells, classes, and links for an adapter."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, object]]] = []
        self._row: list[dict[str, object]] | None = None
        self._cell: list[str] | None = None
        self._cell_class = ""
        self._links: list[tuple[str | None, str]] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        if tag == "tr":
            self._row = []
        elif tag == "td" and self._row is not None:
            self._cell = []
            self._cell_class = attrs_map.get("class", "")
            self._links = []
        elif tag == "a" and self._cell is not None:
            self._anchor_href = attrs_map.get("href")
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)
        if self._anchor_text is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._row is not None and self._cell is not None:
            self._row.append({"text": " ".join(self._cell).strip(), "class": self._cell_class, "links": self._links})
            self._cell = None
        elif tag == "a" and self._anchor_text is not None:
            self._links.append((self._anchor_href, " ".join(self._anchor_text).strip()))
            self._anchor_href = None
            self._anchor_text = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None


def _field_value(row: list[dict[str, object]], rule: dict[str, Any], base_url: str) -> str | int | None:
    raw: str | None = None
    if "link_href_contains" in rule:
        needle = str(rule["link_href_contains"])
        link = next(
            ((href, text) for cell in row for href, text in cell["links"] if href and needle in href), None
        )
        if link:
            raw = link[0] if rule.get("value") == "href" else link[1]
    else:
        cell = next((item for item in row if str(rule.get("cell_class_contains", "")) in str(item["class"])), None)
        if cell is None and "fallback_index" in rule and len(row) > int(rule["fallback_index"]):
            cell = row[int(rule["fallback_index"])]
        if cell:
            raw = str(cell["text"])
    if raw is None or not raw.strip():
        return None
    if rule.get("as") == "integer":
        digits = re.sub(r"[^0-9]", "", raw)
        return int(digits) if digits else None
    if rule.get("as") == "url":
        return urllib.parse.urljoin(base_url, raw)
    return raw.strip()


def parse_results(html: str, base_url: str, adapter: dict[str, Any]) -> list[ParsedResult]:
    parser = SearchTableParser()
    parser.feed(html)
    fields = adapter["result"]["fields"]
    required_href = str(adapter["result"].get("required_link_href_contains", ""))
    parsed: list[ParsedResult] = []
    for row in parser.rows:
        if not row or (required_href and not any(href and required_href in href for cell in row for href, _ in cell["links"])):
            continue
        values = {name: _field_value(row, rule, base_url) for name, rule in fields.items()}
        if not isinstance(values.get("title"), str) or not isinstance(values.get("details_url"), str):
            continue
        parsed.append(ParsedResult(
            title=values["title"], details_url=values["details_url"],
            category=values.get("category") if isinstance(values.get("category"), str) else None,
            seeders=values.get("seeders") if isinstance(values.get("seeders"), int) else None,
            leechers=values.get("leechers") if isinstance(values.get("leechers"), int) else None,
            size=values.get("size") if isinstance(values.get("size"), str) else None,
            uploader=values.get("uploader") if isinstance(values.get("uploader"), str) else None,
        ))
    return parsed


def has_next_page(html: str, current_page: int, adapter: dict[str, Any]) -> bool:
    matches = re.findall(str(adapter.get("pagination", {}).get("href_regex", "(?!)")), html)
    pages = [int(value) for value in matches if str(value).isdigit()]
    return any(page > current_page for page in pages)


def parse_magnet_link(html: str, adapter: dict[str, Any]) -> str | None:
    pattern = str(adapter.get("magnet", {}).get("href_regex", "(?!)"))
    match = re.search(pattern, html, flags=re.IGNORECASE)
    return unescape(match.group(1) if match and match.lastindex else match.group(0)) if match else None


def fetch_magnet_now(result_id: int) -> str | None:
    """Perform one user-initiated detail request, while preserving per-source pacing."""
    with connect() as db:
        item = db.execute(
            """SELECT r.*, s.kind, s.min_delay_seconds, s.current_delay_seconds, s.successful_requests, s.next_allowed_at,
               (SELECT id FROM crawl_jobs WHERE source_id=r.source_id AND query=r.remote_query ORDER BY id DESC LIMIT 1) AS job_id
               FROM results r JOIN sources s ON s.id=r.source_id WHERE r.id=?""", (result_id,)
        ).fetchone()
    if not item:
        raise ValueError("Result or its source no longer exists")
    if item["magnet_link"]:
        return item["magnet_link"]
    if item["next_allowed_at"]:
        allowed_at = datetime.fromisoformat(item["next_allowed_at"].replace("Z", "+00:00"))
        remaining = (allowed_at - utc_now()).total_seconds()
        if remaining > 0:
            raise PacingRequiredError(max(1, int(remaining) + 1))

    try:
        request = urllib.request.Request(item["details_url"], headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
        with urllib.request.urlopen(request, timeout=25) as response:
            html = response.read().decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            http_status = response.status
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as error:
        _record_direct_magnet_result(item, "failed", getattr(error, "code", None), None, error)
        raise RuntimeError(f"{type(error).__name__}: {error}") from error
    except Exception as error:
        _record_direct_magnet_result(item, "failed", None, None, error)
        raise RuntimeError(f"{type(error).__name__}: {error}") from error

    magnet = parse_magnet_link(html, get_adapter(item["kind"]))
    _record_direct_magnet_result(item, "succeeded", http_status, magnet, None)
    return magnet


def _record_direct_magnet_result(item: sqlite3.Row, status: str, http_status: int | None, magnet: str | None, error: Exception | None) -> None:
    with connect() as db:
        current_source = db.execute("SELECT * FROM sources WHERE id=?", (item["source_id"],)).fetchone()
        if not current_source:
            return
        wait_after, adjustment = _adjust_source_delay(db, current_source, succeeded=status == "succeeded")
        next_allowed = iso(utc_now() + timedelta(seconds=wait_after))
        if status == "succeeded":
            db.execute("UPDATE results SET magnet_link=? WHERE id=?", (magnet, item["id"]))
        db.execute("UPDATE sources SET next_allowed_at=? WHERE id=?", (next_allowed, item["source_id"]))
        if item["job_id"] is not None:
            db.execute(
                """INSERT INTO request_log(source_id, job_id, request_type, url, status, http_status, result_count,
                   wait_before_seconds, wait_adjustment_seconds, effective_wait_seconds, error)
                   VALUES (?, ?, 'detail', ?, ?, ?, ?, ?, ?, ?, ?)""",
                (item["source_id"], item["job_id"], item["details_url"], status, http_status,
                 1 if magnet else 0, item["current_delay_seconds"], adjustment, wait_after,
                 f"{type(error).__name__}: {error}" if error else None),
            )


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def run_one_job() -> bool:
    """Run one paced search-page or result-detail request."""
    now = iso(utc_now())
    with connect() as db:
        _finalise_finished_jobs(db)
        job = db.execute(
            """SELECT j.*, s.base_url, s.kind, s.min_delay_seconds, s.current_delay_seconds, s.successful_requests, s.next_allowed_at
               FROM crawl_jobs j JOIN sources s ON s.id=j.source_id
               WHERE j.status IN ('queued', 'retrying') AND j.run_after <= ?
               AND j.page_complete=0
               AND (s.next_allowed_at IS NULL OR s.next_allowed_at <= ?)
               ORDER BY j.run_after, j.id LIMIT 1""", (now, now)
        ).fetchone()
        if job:
            db.execute("UPDATE crawl_jobs SET status='running', attempt_count=attempt_count+1 WHERE id=?", (job["id"],))
            task = job
            request_type = "search"
            url = build_search_url(get_adapter(job["kind"]), job["base_url"], job["query"], job["next_page"])
        else:
            task = db.execute(
                """SELECT d.*, j.query, j.status AS job_status, j.page_complete,
                          s.base_url, s.kind, s.min_delay_seconds, s.current_delay_seconds, s.successful_requests, s.next_allowed_at
                   FROM detail_tasks d
                   JOIN crawl_jobs j ON j.id=d.job_id
                   JOIN sources s ON s.id=d.source_id
                   WHERE d.status IN ('queued', 'retrying') AND d.on_demand=1
                   AND d.run_after <= ? AND (s.next_allowed_at IS NULL OR s.next_allowed_at <= ?)
                   ORDER BY d.run_after, d.id LIMIT 1""", (now, now)
            ).fetchone()
            if not task:
                return False
            db.execute("UPDATE detail_tasks SET status='running', attempt_count=attempt_count+1 WHERE id=?", (task["id"],))
            request_type = "detail"
            url = task["details_url"]

    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
        with urllib.request.urlopen(request, timeout=25) as response:
            html = response.read().decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            http_status = response.status
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as error:
        _reschedule_failure(task, request_type, url, error)
        return True
    except Exception as error:  # preserve the queue instead of killing its worker
        _reschedule_failure(task, request_type, url, error)
        return True

    if request_type == "detail":
        _complete_detail_request(task, url, html, http_status)
    else:
        _complete_search_request(task, url, html, http_status)
    return True


def _complete_search_request(job: sqlite3.Row, url: str, html: str, http_status: int) -> None:
    adapter = get_adapter(job["kind"])
    results = parse_results(html, job["base_url"], adapter)
    more_pages = has_next_page(html, job["next_page"], adapter)
    with connect() as db:
        wait_after, adjustment = _adjust_source_delay(db, job, succeeded=True)
        next_allowed = iso(utc_now() + timedelta(seconds=wait_after))
        new_results = 0
        for item in results:
            already_saved = db.execute(
                "SELECT 1 FROM results WHERE source_id=? AND details_url=?", (job["source_id"], item.details_url)
            ).fetchone()
            if not already_saved:
                new_results += 1
            db.execute(
                """INSERT INTO results(source_id, remote_query, title, category, details_url, size, seeders, leechers, uploader)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_id, details_url) DO UPDATE SET
                     remote_query=excluded.remote_query, title=excluded.title, category=excluded.category,
                     size=excluded.size, seeders=excluded.seeders, leechers=excluded.leechers, uploader=excluded.uploader,
                     discovered_at=CURRENT_TIMESTAMP""",
                (job["source_id"], job["query"], item.title, item.category, item.details_url, item.size, item.seeders, item.leechers, item.uploader),
            )
        db.execute("UPDATE sources SET next_allowed_at=? WHERE id=?", (next_allowed, job["source_id"]))
        if more_pages:
            db.execute(
                """UPDATE crawl_jobs SET status='queued', attempt_count=0, next_page=next_page+1,
                   pages_crawled=pages_crawled+1, results_found=results_found+?, matches_seen=matches_seen+?, run_after=?, last_error=NULL
                   WHERE id=? AND status='running'""",
                (new_results, len(results), next_allowed, job["id"]),
            )
        else:
            db.execute(
                """UPDATE crawl_jobs SET status='complete', attempt_count=0, page_complete=1,
                   pages_crawled=pages_crawled+1, results_found=results_found+?, matches_seen=matches_seen+?, completed_at=CURRENT_TIMESTAMP, last_error=NULL
                   WHERE id=? AND status='running'""",
                (new_results, len(results), job["id"]),
            )
        _record_request(db, job, "search", url, "succeeded", http_status, len(results), adjustment, wait_after)


def _complete_detail_request(task: sqlite3.Row, url: str, html: str, http_status: int) -> None:
    magnet = parse_magnet_link(html, get_adapter(task["kind"]))
    with connect() as db:
        wait_after, adjustment = _adjust_source_delay(db, task, succeeded=True)
        next_allowed = iso(utc_now() + timedelta(seconds=wait_after))
        db.execute("UPDATE results SET magnet_link=? WHERE id=?", (magnet, task["result_id"]))
        db.execute("UPDATE detail_tasks SET status='complete', attempt_count=0, last_error=NULL WHERE id=? AND status='running'", (task["id"],))
        db.execute("UPDATE sources SET next_allowed_at=? WHERE id=?", (next_allowed, task["source_id"]))
        _record_request(db, task, "detail", url, "succeeded", http_status, 1 if magnet else 0, adjustment, wait_after)


def _reschedule_failure(item: sqlite3.Row, request_type: str, url: str, error: Exception) -> None:
    attempts = item["attempt_count"] + 1
    retry_after_seconds = 0
    if isinstance(error, urllib.error.HTTPError):
        retry_after = error.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            retry_after_seconds = min(int(retry_after), 24 * 60 * 60)
        # Authentication and missing-route errors are not transient. A 403 can be
        # temporary source throttling, so it receives the same bounded retry policy.
        if error.code in {401, 404, 410}:
            attempts = MAX_ATTEMPTS
    status = "failed" if attempts >= MAX_ATTEMPTS else "retrying"
    with connect() as db:
        wait_after, adjustment = _adjust_source_delay(db, item, succeeded=False)
        effective_wait = max(wait_after, retry_after_seconds)
        next_run = iso(utc_now() + timedelta(seconds=effective_wait))
        message = f"{type(error).__name__}: {error}"
        if request_type == "search":
            db.execute("UPDATE crawl_jobs SET status=?, run_after=?, last_error=? WHERE id=? AND status='running'", (status, next_run, message, item["id"]))
        else:
            db.execute("UPDATE detail_tasks SET status=?, run_after=?, last_error=? WHERE id=? AND status='running'", (status, next_run, message, item["id"]))
        db.execute("UPDATE sources SET next_allowed_at=? WHERE id=?", (next_run, item["source_id"]))
        _record_request(db, item, request_type, url, "failed", getattr(error, "code", None), None, adjustment, effective_wait, message)


def _adjust_source_delay(db: sqlite3.Connection, source: sqlite3.Row, succeeded: bool) -> tuple[int, int]:
    current = source["current_delay_seconds"]
    minimum = source["min_delay_seconds"]
    if not succeeded:
        updated, streak, adjustment = current + 10, 0, 10
    else:
        streak = source["successful_requests"] + 1
        if streak >= 5 and current > minimum:
            updated, streak = max(minimum, current - 5), 0
            adjustment = updated - current
        else:
            updated, adjustment = current, 0
    db.execute("UPDATE sources SET current_delay_seconds=?, successful_requests=? WHERE id=?", (updated, streak, source["source_id"] if "source_id" in source.keys() else source["id"]))
    return updated, adjustment


def _record_request(db: sqlite3.Connection, item: sqlite3.Row, request_type: str, url: str, status: str, http_status: int | None, result_count: int | None, adjustment: int, effective_wait: int, error: str | None = None) -> None:
    job_id = item["job_id"] if request_type == "detail" else item["id"]
    detail_task_id = item["id"] if request_type == "detail" else None
    page = None if request_type == "detail" else item["next_page"]
    db.execute(
        """INSERT INTO request_log(source_id, job_id, detail_task_id, request_type, url, page, status, http_status, result_count,
           wait_before_seconds, wait_adjustment_seconds, effective_wait_seconds, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (item["source_id"], job_id, detail_task_id, request_type, url, page, status, http_status, result_count,
         item["current_delay_seconds"], adjustment, effective_wait, error),
    )


def _finalise_finished_jobs(db: sqlite3.Connection) -> None:
    db.execute(
        """UPDATE crawl_jobs AS job SET status='complete', completed_at=COALESCE(completed_at, CURRENT_TIMESTAMP)
           WHERE status IN ('queued', 'retrying') AND page_complete=1
           AND NOT EXISTS (SELECT 1 FROM detail_tasks WHERE job_id=job.id AND on_demand=0 AND status IN ('queued', 'running', 'retrying'))"""
    )
