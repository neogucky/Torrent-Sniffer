from unittest.mock import patch

from app import crawler, database

PAGE = """<table><tr><td><a href="/torrent/1">Example Movie 1080p</a></td>
<td class="seeds">12</td><td class="leeches">3</td><td>today</td><td class="size">4 GB</td></tr></table>"""


def queue(client, source, query="Example Movie"):
    response = client.post(
        "/api/jobs", json={"source_id": source["id"], "query": query}
    )
    assert response.status_code == 201, response.text
    return response.json()


def crawl(client, source, query="Example Movie", html=PAGE):
    job = queue(client, source, query)
    with database.connect() as db:
        db.execute("UPDATE sources SET next_allowed_at=NULL")
    with patch("app.crawler.fetch_source_html", return_value=(html, 200)):
        assert crawler.run_one_job()
    return job


def wishes(client, state="active"):
    return client.get("/api/wishlist", params={"state": state}).json()


def test_summary_counts_only_active_wishes(client, source):
    assert client.get("/api/summary").json()["active_wishes"] == 0
    first = client.post("/api/wishlist", json={"query": "First movie"}).json()
    queue(client, source, "Second movie")
    assert client.get("/api/summary").json()["active_wishes"] == 2
    client.patch(f"/api/wishlist/{first['id']}", json={"status": "archived"})
    assert len(wishes(client, "archived")) == 1
    assert client.get("/api/summary").json()["active_wishes"] == 1
    client.patch(f"/api/wishlist/{first['id']}", json={"status": "active"})
    assert client.get("/api/summary").json()["active_wishes"] == 2
    client.delete(f"/api/wishlist/{first['id']}")
    assert client.get("/api/summary").json()["active_wishes"] == 1


def test_auto_add_empty_crawl_and_normalized_dedup(client, source):
    crawl(client, source, html="<table></table>")
    queue(client, source, "  MOVIE.example ")
    rows = wishes(client)
    assert len(rows) == 1
    assert rows[0]["result_count"] == 0
    assert rows[0]["crawl_count"] == 2
    assert rows[0]["last_crawled_at"]
    assert rows[0]["active_crawls"] == 1
    assert (
        client.post(
            "/api/jobs", json={"source_id": source["id"], "query": " ... "}
        ).status_code
        == 422
    )


def test_result_links_survive_overlapping_crawls_and_dedup(client, source):
    crawl(client, source)
    crawl(client, source, "Movie")
    crawl(client, source)
    rows = wishes(client)
    assert {r["query"]: r["result_count"] for r in rows} == {
        "Example Movie": 1,
        "Movie": 1,
    }
    for row in rows:
        linked = client.get("/api/results", params={"wishlist_id": row["id"]}).json()
        assert len(linked) == 1
    with database.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 1


def test_manual_download_archives_query_and_crawl_links_only_on_success(client, source):
    crawl(client, source)
    # A wish can be fulfilled by a local search even without its own crawl.
    client.post("/api/wishlist", json={"query": "Example", "kind": "series"})
    client.post("/api/wishlist", json={"query": "Unrelated"})
    result = client.get("/api/results", params={"q": "Example"}).json()[0]
    with database.connect() as db:
        db.execute(
            "UPDATE results SET magnet_link=? WHERE id=?",
            ("magnet:?xt=urn:btih:123", result["id"]),
        )
    url = f"/api/results/{result['id']}/qbittorrent"
    with patch("app.main.add_to_qbittorrent", side_effect=RuntimeError("failed")):
        assert (
            client.post(
                url, json={"location_label": "Movies", "query": "example"}
            ).status_code
            == 502
        )
    assert len(wishes(client)) == 3
    with patch("app.main.add_to_qbittorrent"):
        assert (
            client.post(
                url, json={"location_label": "Movies", "query": "example"}
            ).status_code
            == 204
        )
    assert [w["query"] for w in wishes(client)] == ["Unrelated"]
    assert len(wishes(client, "archived")) == 2
    # Re-crawling an archived term must not silently restore it.
    crawl(client, source)
    assert len(wishes(client, "archived")) == 2
    archived = wishes(client, "archived")[0]
    assert (
        client.patch(
            f"/api/wishlist/{archived['id']}", json={"status": "active"}
        ).status_code
        == 200
    )
    assert len(wishes(client)) == 2


def test_external_download_needs_magnet_and_archives(client, source):
    crawl(client, source)
    result = client.get("/api/results").json()[0]
    url = f"/api/results/{result['id']}/downloaded"
    assert client.post(url, json={}).status_code == 409
    assert len(wishes(client)) == 1
    with database.connect() as db:
        db.execute("UPDATE results SET magnet_link=?", ("magnet:?xt=urn:btih:abc",))
    assert client.post(url, json={}).status_code == 204
    assert not wishes(client)


def test_delete_wish_keeps_results_and_requires_stopped_crawls(client, source):
    job = queue(client, source)
    wish = wishes(client)[0]
    url = f"/api/wishlist/{wish['id']}"
    assert client.delete(url).status_code == 409
    with database.connect() as db:
        db.execute("UPDATE crawl_jobs SET status='stopped' WHERE id=?", (job["id"],))
    assert client.delete(url).status_code == 204
    assert not wishes(client)


def test_migrate_history_and_restart_preserves_source_kind(client, source):
    with database.connect() as db:
        db.execute("DROP TABLE wishlist_results")
        db.execute("DROP TABLE wishlist")
        db.execute("DROP INDEX crawl_jobs_wishlist")
        db.execute("ALTER TABLE crawl_jobs DROP COLUMN wishlist_id")
        db.execute(
            "INSERT INTO crawl_jobs(source_id, query, status) VALUES (?, 'Example Movie', 'complete')",
            (source["id"],),
        )
        db.execute(
            "INSERT INTO results(source_id, remote_query, title, details_url) VALUES (?, 'Example Movie', 'Example Movie', '/torrent/1')",
            (source["id"],),
        )
        db.execute("UPDATE sources SET kind='rutracker'")
    database.initialise()
    database.initialise()
    assert len(wishes(client)) == 1
    assert wishes(client)[0]["result_count"] == 1
    assert wishes(client)[0]["crawl_count"] == 1
    assert client.get("/api/sources").json()[0]["kind"] == "rutracker"


def test_download_from_different_manual_query_matches_new_wish_title(client, source):
    crawl(client, source, "Movie")
    client.post("/api/wishlist", json={"query": "EXAMPLE.movie", "kind": "movie"})
    client.post("/api/wishlist", json={"query": "Examples", "kind": "movie"})
    result = client.get("/api/results", params={"q": "Example"}).json()[0]
    with database.connect() as db:
        db.execute("UPDATE results SET magnet_link=?", ("magnet:?xt=urn:btih:abc",))
    with patch("app.main.add_to_qbittorrent"):
        assert (
            client.post(
                f"/api/results/{result['id']}/qbittorrent",
                json={"location_label": "Movies", "query": "Example"},
            ).status_code
            == 204
        )
    assert [wish["query"] for wish in wishes(client)] == ["Examples"]
    assert len(wishes(client, "archived")) == 2


def test_manually_classify_auto_created_wish_without_losing_history(client, source):
    queue(client, source)
    response = client.post(
        "/api/wishlist", json={"query": "Example Movie", "kind": "movie"}
    )
    assert response.status_code == 201
    assert response.json()["kind"] == "movie"
    assert len(wishes(client)) == 1
    assert wishes(client)[0]["crawl_count"] == 1


def test_interrupted_history_migration_can_retry(client, source):
    import pytest

    with database.connect() as db:
        db.execute("DROP INDEX crawl_jobs_wishlist")
        db.execute("ALTER TABLE crawl_jobs DROP COLUMN wishlist_id")
        db.execute(
            "INSERT INTO crawl_jobs(source_id, query) VALUES (?, 'Example Movie')",
            (source["id"],),
        )
    with patch(
        "app.wishlist.ensure_wish", side_effect=RuntimeError("simulated interruption")
    ):
        with pytest.raises(RuntimeError, match="interruption"):
            database.initialise()
    database.initialise()
    assert wishes(client)[0]["crawl_count"] == 1
