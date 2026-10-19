import io
import urllib.parse
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from app import crawler, database
from app.adapters import get_adapter

SEARCH_PAGE = (Path(__file__).parent / "fixtures/rutracker-search.html").read_text()


def test_only_torrent_table_title_cells_are_results():
    results = crawler.parse_results(
        SEARCH_PAGE, "https://forum.example.invalid", get_adapter("rutracker")
    )
    assert len(results) == 2
    assert all("Ninja Turtles" in item.title for item in results)
    assert results[0].details_url.endswith("/forum/viewtopic.php?t=101")
    assert results[0].category == "Movies"
    assert results[0].uploader == "Fixture author"
    assert results[0].size_bytes == 8 * 1024**3
    assert results[0].seeders == 24 and results[0].leechers == 3
    assert results[0].torrent_created_at == "2024-01-01"


def test_help_topic_is_not_a_result_when_search_has_no_matches():
    html = '<table><tr><td><a href="viewtopic.php?t=999">Помощь по поиску</a></td></tr></table>'
    assert not crawler.parse_results(
        html, "https://forum.example.invalid", get_adapter("rutracker")
    )


def test_authenticated_search_keeps_query_and_collects_all_pages(client):
    source = client.post(
        "/api/sources",
        json={
            "base_url": "https://forum.example.invalid",
            "kind": "rutracker",
            "min_delay_seconds": 1,
            "auth_mode": "cookie",
            "auth_cookie": "bb_session=fixture-session",
        },
    ).json()
    job = client.post(
        "/api/jobs", json={"source_id": source["id"], "query": "Ninja Turtles"}
    ).json()
    requests = []

    class FixtureHTTPS(urllib.request.BaseHandler):
        handler_order = 100

        def https_open(self, request):
            assert urllib.parse.urlsplit(request.full_url).hostname == "forum.example.invalid"
            assert request.get_method() == "GET"
            assert "bb_session=fixture-session" in request.get_header("Cookie")
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
            requests.append(params)
            assert params["nm"] == ["Ninja Turtles"]
            assert params["f[]"] == ["-1"]
            if params["start"] == ["0"]:
                html = SEARCH_PAGE
            else:
                assert params["start"] == ["50"]
                # Last page repeats one release and adds another: count distinct releases.
                html = SEARCH_PAGE.replace("t=102", "t=103").replace("start=50", "start=0")
            headers = Message()
            headers["Content-Type"] = "text/html; charset=windows-1251"
            response = urllib.response.addinfourl(
                io.BytesIO(html.encode("windows-1251")), headers, request.full_url, 200
            )
            response.msg = "OK"
            return response

    builder = urllib.request.build_opener
    with patch(
        "app.source_auth.urllib.request.build_opener",
        side_effect=lambda *handlers: builder(FixtureHTTPS(), *handlers),
    ):
        assert crawler.run_one_job()
        with database.connect() as db:
            db.execute("UPDATE sources SET next_allowed_at=NULL")
            db.execute("UPDATE crawl_jobs SET run_after=CURRENT_TIMESTAMP")
        assert crawler.run_one_job()
        assert not crawler.run_one_job()
    assert [request["start"] for request in requests] == [["0"], ["50"]]
    saved_job = client.get("/api/jobs").json()[0]
    assert saved_job["status"] == "complete"
    assert saved_job["pages_crawled"] == 2
    assert saved_job["results_found"] == 3
    assert saved_job["matches_seen"] == 4
    assert len(client.get("/api/results").json()) == 3
    assert client.get("/api/wishlist").json()[0]["result_count"] == 3
    logs = client.get(f"/api/jobs/{job['id']}/requests").json()
    assert all(log["error"] is None for log in logs)
