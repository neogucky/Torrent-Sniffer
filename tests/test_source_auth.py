import io
import os
import urllib.request
from email.message import Message
from unittest.mock import patch

import pytest

from app import crawler, database, main, source_auth
from app.adapters import get_adapter

LOGIN = '<form><input name="login_username"></form>'
LOGGED = '<a id="logged-in-username">account</a>'


class Response(io.BytesIO):
    def __init__(self, text, charset="windows-1251"):
        super().__init__(text.encode(charset))
        self.headers = Message()
        self.headers["Content-Type"] = f"text/html; charset={charset}"
        self.status = 200


def create(client, **kwargs):
    return client.post(
        "/api/sources",
        json={
            "base_url": "https://forum.example.invalid",
            "kind": "rutracker",
            "min_delay_seconds": 1,
            "auth_mode": "password",
            "auth_username": "private-user",
            "auth_password": "private-password",
            **kwargs,
        },
    )


def test_write_only_encrypted_login_and_keep_blank(client):
    response = create(client)
    assert response.status_code == 201, response.text
    source = response.json()
    for payload in (response.text, client.get("/api/sources").text):
        assert "private-user" not in payload
        assert "private-password" not in payload
    with database.connect() as db:
        row = db.execute("SELECT * FROM source_auth").fetchone()
        assert "private-password" not in row["secret"]
        assert source_auth._read(row)["password"] == "private-password"
    assert (
        os.stat(database.DB_PATH.parent / "source-secrets.key").st_mode & 0o777 == 0o600
    )
    assert (
        client.put(
            f"/api/sources/{source['id']}",
            json={
                "base_url": source["base_url"],
                "kind": "rutracker",
                "auth_mode": "password",
            },
        ).status_code
        == 200
    )
    # Validation errors must not echo secret input.
    bad = create(client, auth_cookie="sensitive=" + "x" * 17000)
    assert bad.status_code == 422
    assert "sensitive=" not in bad.text


def test_login_reuse_cookie_restart_and_charset(client):
    source = create(client, auth_username="имя", auth_password="пароль").json()
    captured = []

    def open_request(req, timeout):
        captured.append(req)
        if req.data:
            assert b"login_username=%E8%EC%FF" in req.data
            # Simulate the standard CookieProcessor capturing Set-Cookie.
            jar.set_cookie(
                source_auth._cookie(
                    "bb_session", "session-secret", "forum.example.invalid"
                )
            )
        return Response(LOGIN if len(captured) == 1 else LOGGED + " Русский")

    def build(*handlers):
        nonlocal jar
        jar = next(
            h.cookiejar
            for h in handlers
            if isinstance(h, urllib.request.HTTPCookieProcessor)
        )
        from types import SimpleNamespace

        return SimpleNamespace(open=open_request)

    jar = None
    with patch("app.source_auth.urllib.request.build_opener", side_effect=build):
        html, _ = source_auth.fetch_source_html(
            source["id"],
            source["base_url"] + "/forum/tracker.php",
            get_adapter("rutracker"),
        )
    assert "Русский" in html
    assert len(captured) == 3
    with database.connect() as db:
        config = source_auth._read(db.execute("SELECT * FROM source_auth").fetchone())
        assert config["cookies"][0]["value"] == "session-secret"
    # A fresh opener rebuilds the saved session from encrypted storage.
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.return_value = Response(LOGGED)
        source_auth.fetch_source_html(
            source["id"],
            source["base_url"] + "/forum/viewtopic.php?t=1",
            get_adapter("rutracker"),
        )
        assert build.return_value.open.call_count == 1
        cookie_handler = build.call_args.args[1]
        assert next(iter(cookie_handler.cookiejar)).value == "session-secret"


def test_captcha_and_expired_cookie_stop_with_actionable_error(client):
    source = create(client).json()
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.return_value = Response('<input name="cap_sid">')
        with pytest.raises(source_auth.SourceAuthError, match="CAPTCHA"):
            source_auth.fetch_source_html(
                source["id"],
                source["base_url"] + "/forum/tracker.php",
                get_adapter("rutracker"),
            )
        assert build.return_value.open.call_count == 1
    update = {
        "base_url": source["base_url"],
        "kind": "rutracker",
        "auth_mode": "cookie",
        "auth_cookie": "bb_session=manual-secret",
    }
    assert client.put(f"/api/sources/{source['id']}", json=update).status_code == 200
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.return_value = Response(LOGIN)
        response = client.post(f"/api/sources/{source['id']}/login")
        assert response.status_code == 502
        assert "expired" in response.text
        assert build.return_value.open.call_count == 1
        assert "manual-secret" not in response.text
    # No repeated automatic credential attempts until settings change or test is requested.
    with pytest.raises(source_auth.SourceAuthError, match="expired"):
        source_auth.fetch_source_html(
            source["id"],
            source["base_url"] + "/forum/tracker.php",
            get_adapter("rutracker"),
        )


def test_auth_is_admin_only_and_bound_to_origin(client):
    source = create(client).json()
    main.app.dependency_overrides[main.require_user] = lambda: {
        "id": 2,
        "is_admin": False,
    }
    assert (
        client.put(
            f"/api/sources/{source['id']}",
            json={"base_url": source["base_url"], "kind": "default"},
        ).status_code
        == 403
    )
    assert client.delete(f"/api/sources/{source['id']}").status_code == 403
    main.app.dependency_overrides[main.require_user] = lambda: {
        "id": 1,
        "is_admin": True,
    }
    with pytest.raises(source_auth.SourceAuthError, match="origin"):
        source_auth.fetch_source_html(
            source["id"],
            "https://other.example.invalid/forum/",
            get_adapter("rutracker"),
        )
    redirect = source_auth._SameOriginRedirect(source["base_url"])
    req = urllib.request.Request(source["base_url"])
    with pytest.raises(source_auth.SourceAuthError, match="origin"):
        redirect.redirect_request(
            req, None, 302, "", Message(), "https://other.example.invalid"
        )
    assert (
        client.put(
            f"/api/sources/{source['id']}",
            json={"base_url": "https://new.example.invalid", "kind": "rutracker"},
        ).status_code
        == 200
    )
    assert client.get("/api/sources").json()[0]["auth"]["mode"] == "none"
    assert create(client, base_url="http://insecure.example.invalid").status_code == 422
    assert (
        create(client, base_url="https://user:password@example.invalid").status_code
        == 422
    )


def test_adapter_encoding_pagination_and_metadata(client):
    adapter = get_adapter("rutracker")
    url = crawler.build_search_url(
        adapter, "https://forum.example.invalid", "Кино & TV", 2
    )
    assert "start=50" in url and "%CA%E8%ED%EE" in url and "%26" in url
    html = """<table id="tor-tbl"><tr><td></td><td></td><td class="f-name-col">Movies</td>
    <td class="t-title-col"><a href="viewtopic.php?t=7">Кино &amp; TV</a></td><td class="u-name-col">Author</td>
    <td class="tor-size" data-ts_text="4294967296"><a href="dl.php?t=7">4 GB</a></td>
    <td class="seedmed"><b>12</b></td><td class="leechmed">3</td><td>20</td>
    <td data-ts_text="1704067200">01-Янв-24</td></tr></table>
    <a href="tracker.php?nm=title&amp;start=50">2</a>"""
    result = crawler.parse_results(html, "https://forum.example.invalid", adapter)[0]
    assert result.title == "Кино & TV"
    assert result.details_url == "https://forum.example.invalid/forum/viewtopic.php?t=7"
    assert result.size_bytes == 4294967296
    assert result.torrent_created_at == "2024-01-01"
    assert result.seeders == 12 and result.leechers == 3
    assert crawler.has_next_page(html, 1, adapter)
    assert not crawler.has_next_page(html, 2, adapter)
    assert (
        crawler.parse_magnet_link(
            '<a href="magnet:?xt=urn:btih:abc&amp;dn=Example">', adapter
        )
        == "magnet:?xt=urn:btih:abc&dn=Example"
    )


def test_auth_error_fails_crawl_without_false_completion(client):
    source = create(client).json()
    client.post("/api/jobs", json={"source_id": source["id"], "query": "Example"})
    with patch(
        "app.crawler.fetch_source_html",
        side_effect=source_auth.SourceAuthError("Use a browser session cookie"),
    ):
        assert crawler.run_one_job()
    job = client.get("/api/jobs").json()[0]
    assert job["status"] == "failed"
    assert job["pages_crawled"] == 0
    assert "browser session" in job["last_error"]


def test_cookie_processor_sends_and_persists_real_response_cookies(client):
    from urllib.response import addinfourl

    source = create(client).json()
    seen = []

    class FakeHTTPS(urllib.request.BaseHandler):
        handler_order = 100

        def https_open(self, request):
            seen.append((request.full_url, request.data, request.get_header("Cookie")))
            headers = Message()
            # Deliberately no charset: the adapter must provide the fallback.
            headers["Content-Type"] = "text/html"
            if request.data:
                headers["Set-Cookie"] = (
                    "bb_session=renewed-session; Path=/; Secure; HttpOnly"
                )
                body = LOGGED
            elif request.get_header("Cookie") == "bb_session=renewed-session":
                body = LOGGED + " Кино"
            else:
                body = LOGIN
            response = addinfourl(
                io.BytesIO(body.encode("windows-1251")), headers, request.full_url, 200
            )
            response.msg = "OK"
            return response

    builder = urllib.request.build_opener
    with patch(
        "app.source_auth.urllib.request.build_opener",
        side_effect=lambda *handlers: builder(*handlers, FakeHTTPS()),
    ):
        for _ in range(2):
            html, code = source_auth.fetch_source_html(
                source["id"],
                source["base_url"] + "/forum/tracker.php",
                get_adapter("rutracker"),
            )
            assert code == 200 and "Кино" in html
    assert len(seen) == 4
    assert seen[0][2] is None
    assert seen[2][2] == seen[3][2] == "bb_session=renewed-session"


def test_invalid_password_does_not_retry_or_log_secret(client):
    source = create(client).json()
    client.post("/api/jobs", json={"source_id": source["id"], "query": "Example"})
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.side_effect = [Response(LOGIN), Response(LOGIN)]
        assert crawler.run_one_job()
        assert build.return_value.open.call_count == 2
    assert client.get("/api/jobs").json()[0]["status"] == "failed"
    for response in [
        client.get("/api/jobs"),
        client.get("/api/jobs/1/requests"),
        client.get("/api/sources"),
    ]:
        assert "private-password" not in response.text
        assert "private-user" not in response.text


def test_cookie_import_and_lost_key_recovery(client, monkeypatch):
    source = create(
        client, auth_mode="cookie", auth_cookie="bb_session=browser-secret"
    ).json()
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.return_value = Response(LOGGED)
        source_auth.fetch_source_html(
            source["id"],
            source["base_url"] + "/forum/tracker.php",
            get_adapter("rutracker"),
        )
        jar = build.call_args.args[1].cookiejar
        assert next(iter(jar)).value == "browser-secret"
    monkeypatch.setenv("SOURCE_SECRETS_KEY", source_auth.Fernet.generate_key().decode())
    with pytest.raises(source_auth.SourceAuthError, match="decrypt"):
        source_auth.fetch_source_html(
            source["id"],
            source["base_url"] + "/forum/tracker.php",
            get_adapter("rutracker"),
        )
    response = client.put(
        f"/api/sources/{source['id']}",
        json={
            "base_url": source["base_url"],
            "kind": "rutracker",
            "auth_mode": "cookie",
            "auth_cookie": "bb_session=replaced-secret",
        },
    )
    assert response.status_code == 200


def test_new_endpoints_require_sign_in(client):
    main.app.dependency_overrides.clear()
    assert client.get("/api/wishlist").status_code == 401
    assert client.post("/api/wishlist", json={"query": "Example"}).status_code == 401
    assert client.post("/api/sources/1/login").status_code == 401
    assert client.post("/api/results/1/downloaded", json={}).status_code == 401


def test_authenticated_throttling_retains_retry_after(client):
    source = create(client).json()
    client.post("/api/jobs", json={"source_id": source["id"], "query": "Example"})
    headers = Message()
    headers["Retry-After"] = "120"
    error = source_auth.SourceHTTPError(429, headers)
    with patch("app.crawler.fetch_source_html", side_effect=error):
        assert crawler.run_one_job()
    job = client.get("/api/jobs").json()[0]
    assert job["status"] == "retrying"
    log = client.get(f"/api/jobs/{job['id']}/requests").json()[0]
    assert log["http_status"] == 429 and log["effective_wait_seconds"] == 120


def test_unsupported_search_characters_are_rejected_without_queuing(client):
    source = create(client).json()
    response = client.post(
        "/api/jobs", json={"source_id": source["id"], "query": "电影"}
    )
    assert response.status_code == 422
    assert not client.get("/api/jobs").json()


def test_password_encoding_failure_is_actionable_and_redacted(client):
    source = create(client, auth_password="private-password-😀").json()
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.return_value = Response(LOGIN)
        response = client.post(f"/api/sources/{source['id']}/login")
    assert response.status_code == 502
    assert "browser session" in response.text
    assert "private-password" not in response.text


@pytest.mark.parametrize(
    ("phase", "responses"),
    [
        ("opening the login page", []),
        ("submitting the login form", [LOGIN]),
        ("loading the requested page after login", [LOGIN, LOGGED]),
    ],
)
def test_403_reports_exact_stage_without_password_claim(client, phase, responses):
    source = create(client).json()
    denied = urllib.error.HTTPError(
        source["base_url"] + "/forum/login.php", 403, "Forbidden", Message(), None
    )
    with patch("app.source_auth.urllib.request.build_opener") as build:
        build.return_value.open.side_effect = [Response(html) for html in responses] + [
            denied
        ]
        response = client.post(f"/api/sources/{source['id']}/login")
        assert build.return_value.open.call_count == len(responses) + 1
        # A fresh password session never probes the protected tracker before login.
        assert (
            build.return_value.open.call_args_list[0]
            .args[0]
            .full_url.endswith("/forum/login.php")
        )
    assert response.status_code == 502
    message = response.json()["detail"]
    assert phase in message
    assert "does not establish" in message
    assert "private-password" not in message and "private-user" not in message
    public = client.get("/api/sources").json()[0]["auth"]
    assert public["last_error"] == message
    with database.connect() as db:
        row = db.execute("SELECT * FROM source_auth").fetchone()
        assert (
            row["last_error"] is None
        )  # retain paced retries for transient HTTP errors
        assert row["last_request_error"] == message


def test_login_bootstrap_retains_hidden_fields_and_form_session(client):
    from urllib.response import addinfourl

    source = create(client).json()
    seen = []
    login_url = source["base_url"] + "/forum/login.php"
    target = source["base_url"] + "/forum/tracker.php"

    class FormSource(urllib.request.BaseHandler):
        handler_order = 100

        def https_open(self, request):
            seen.append(request)
            headers = Message()
            headers["Content-Type"] = "text/html; charset=windows-1251"
            if len(seen) == 1:
                assert request.full_url == login_url
                headers["Set-Cookie"] = "prelogin=form-session; Path=/; Secure"
                html = """<form><input type="hidden" name="unrelated" value="ignore"></form>
                    <form><input name="login_username"><input type="hidden" name="form_token" value="fake-form-token">
                    <input type="hidden" name="login_password" value="do-not-use"></form>"""
            elif request.data:
                fields = urllib.parse.parse_qs(request.data.decode())
                assert fields["form_token"] == ["fake-form-token"]
                assert "unrelated" not in fields
                assert fields["login_password"] == ["private-password"]
                assert request.get_header("Cookie") == "prelogin=form-session"
                assert request.get_header("Referer") == login_url
                assert request.get_header("Origin") == source["base_url"]
                headers["Set-Cookie"] = (
                    "bb_session=authenticated-session; Path=/; Secure"
                )
                html = LOGGED
            else:
                assert request.full_url == target
                assert "bb_session=authenticated-session" in request.get_header(
                    "Cookie"
                )
                html = LOGGED
            result = addinfourl(
                io.BytesIO(html.encode("windows-1251")), headers, request.full_url, 200
            )
            result.msg = "OK"
            return result

    builder = urllib.request.build_opener
    with patch(
        "app.source_auth.urllib.request.build_opener",
        side_effect=lambda *handlers: builder(*handlers, FormSource()),
    ):
        html, code = source_auth.fetch_source_html(
            source["id"], target, get_adapter("rutracker")
        )
    assert code == 200 and html == LOGGED
    assert [request.get_method() for request in seen] == ["GET", "POST", "GET"]


def test_diagnostic_column_upgrade_preserves_saved_credentials(client):
    assert create(client).status_code == 201
    with database.connect() as db:
        before = db.execute("SELECT secret FROM source_auth").fetchone()["secret"]
        db.execute("ALTER TABLE source_auth DROP COLUMN last_request_error")
    database.initialise()
    with database.connect() as db:
        row = db.execute("SELECT * FROM source_auth").fetchone()
        assert row["secret"] == before
        assert source_auth._read(row)["password"] == "private-password"
    assert client.get("/api/sources").json()[0]["auth"]["mode"] == "password"


def test_detail_request_retains_http_failure_status(client):
    source = create(client).json()
    job = client.post(
        "/api/jobs", json={"source_id": source["id"], "query": "Example"}
    ).json()
    with database.connect() as db:
        result_id = db.execute(
            "INSERT INTO results(source_id, remote_query, title, details_url) VALUES (?, ?, ?, ?)",
            (
                source["id"],
                "Example",
                "Example",
                source["base_url"] + "/forum/viewtopic.php?t=1",
            ),
        ).lastrowid
    with patch(
        "app.crawler.fetch_source_html",
        side_effect=source_auth.SourceHTTPError(
            403, Message(), "checking the saved session"
        ),
    ):
        response = client.post(f"/api/results/{result_id}/magnet")
    assert response.status_code == 502
    log = client.get(f"/api/jobs/{job['id']}/requests").json()[0]
    assert log["http_status"] == 403
    assert "checking the saved session" in log["error"]
