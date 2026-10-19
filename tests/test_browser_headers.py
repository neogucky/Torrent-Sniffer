import io
import urllib.request
from email.message import Message
from unittest.mock import patch
from urllib.response import addinfourl

import pytest

from app import database, main, source_auth
from app.adapters import get_adapter

BASE = "https://browser-headers.example.invalid"
UA = "Mozilla/5.0 (Test browser) Example/123.0"
COOKIE = "bb_session=private-session; cf_clearance=private-clearance"
HEADERS = f'User-Agent: {UA}\nCookie: {COOKIE}\nAccept: text/html,application/xhtml+xml\nAccept-Language: de-DE,de;q=0.9\nSec-CH-UA: "Test Browser";v="123"\nSec-CH-UA-Mobile: ?0\nSec-CH-UA-Platform: "macOS"'


def extract(client, headers=HEADERS, base_url=BASE):
    return client.post(
        "/api/source-auth/parse-request-headers",
        json={"headers": headers, "base_url": base_url},
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "GET /forum/tracker.php HTTP/1.1\nHost: browser-headers.example.invalid\n",
        ":method: GET\n:scheme: https\n:authority: browser-headers.example.invalid\n:path: /forum/tracker.php\n",
        "GET /forum/tracker.php HTTP/2\n",
    ],
)
def test_extracts_browser_headers_from_common_formats_without_saving(client, prefix):
    with patch("app.source_auth.urllib.request.build_opener") as opener:
        response = extract(client, (prefix + HEADERS).replace("\n", "\r\n"))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["cookie"] == COOKIE and data["cookie_count"] == 2
    assert data["browser_headers"] == {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "de-DE,de;q=0.9",
        "Sec-CH-UA": '"Test Browser";v="123"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"macOS"',
    }
    assert response.headers["cache-control"] == "no-store"
    opener.assert_not_called()
    with database.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM source_auth").fetchone()[0] == 0


def test_unrelated_headers_are_never_extracted_or_persisted(client):
    response = extract(
        client,
        HEADERS
        + "\nAuthorization: private-bearer\nProxy-Authorization: private-proxy\nAccept-Encoding: gzip, br\nConnection: keep-alive\nContent-Length: 999\nReferer: https://elsewhere.example.invalid/private-ref\nSec-Fetch-Site: none",
    )
    assert response.status_code == 200
    for secret in ["private-bearer", "private-proxy", "private-ref", "gzip"]:
        assert secret not in response.text
    assert set(response.json()["browser_headers"]) == {
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Sec-CH-UA",
        "Sec-CH-UA-Mobile",
        "Sec-CH-UA-Platform",
    }


@pytest.mark.parametrize(
    "headers,expected",
    [
        (f"User-Agent: {UA}", "Cookie is missing"),
        (f"Cookie: {COOKIE}", "User-Agent is missing"),
        (HEADERS + "\nuser-agent: private-secret", "more than once"),
        (HEADERS + "\nCookie: bb_session=private-secret", "repeats a cookie name"),
        ("HTTP/1.1 200 OK\n" + HEADERS, "not a response"),
        (HEADERS + "\nSet-Cookie: private-secret", "response headers"),
        (HEADERS + "\n:status: 200", "response headers"),
        (
            "curl 'https://example.invalid' -H 'Cookie: private-secret'",
            "Copy Request Headers",
        ),
        (HEADERS + "\nprivate-secret", "same line"),
        (HEADERS + "\n\nprivate-secret", "request body"),
        (HEADERS + "\nX-Other: private-secret\x00", "plain text"),
        (HEADERS + "\nX-Other: private-secret\r", "plain text"),
        (HEADERS + "\nHost: different.example.invalid", "different source"),
        (
            "GET https://different.example.invalid/page HTTP/1.1\n" + HEADERS,
            "different source",
        ),
        (HEADERS + "\nHost: https://private-secret", "invalid hostname"),
        (
            HEADERS
            + "\nHost: browser-headers.example.invalid\n:authority: different.example.invalid",
            "conflicting hostnames",
        ),
        (
            HEADERS + "\n:scheme: http\n:authority: browser-headers.example.invalid",
            "different source",
        ),
    ],
)
def test_invalid_import_is_actionable_and_does_not_echo_inputs(
    client, headers, expected
):
    response = extract(client, headers)
    assert response.status_code == 422, response.text
    assert expected in response.json()["detail"]
    assert (
        "private-secret" not in response.text and "private-session" not in response.text
    )
    assert "private-clearance" not in response.text


def test_multiple_http2_cookie_lines_and_lowercase_names(client):
    response = extract(
        client, f"user-agent: {UA}\ncookie: bb_session=one\ncookie: cf_clearance=two"
    )
    assert response.status_code == 200
    assert response.json()["cookie"] == "bb_session=one; cf_clearance=two"


def test_invalid_source_url_and_oversized_input_are_redacted(client):
    response = extract(client, base_url="https://[private-secret")
    assert response.status_code == 422 and "private-secret" not in response.text
    response = extract(client, "private-secret" * 4000)
    assert response.status_code == 422 and "private-secret" not in response.text


def test_import_requires_administrator(client):
    main.app.dependency_overrides.pop(main.require_admin)
    main.app.dependency_overrides[main.require_user] = lambda: {
        "id": 2,
        "is_admin": False,
    }
    assert extract(client).status_code == 403
    main.app.dependency_overrides.clear()
    assert extract(client).status_code == 401


def test_saved_browser_context_is_encrypted_sent_and_kept_across_restart(client):
    data = extract(client).json()
    body = {
        "base_url": BASE,
        "kind": "rutracker",
        "auth_mode": "cookie",
        "auth_cookie": data["cookie"],
        "auth_browser_headers": data["browser_headers"],
        "min_delay_seconds": 1,
    }
    response = client.post("/api/sources", json=body)
    assert response.status_code == 201, response.text
    source = response.json()
    assert UA not in response.text and "private-session" not in response.text
    with database.connect() as db:
        row = db.execute(
            "SELECT * FROM source_auth WHERE source_id=?", (source["id"],)
        ).fetchone()
        assert UA not in row["secret"] and "private-clearance" not in row["secret"]
        assert source_auth._read(row)["browser_headers"] == data["browser_headers"]
    seen = []

    class FakeHTTPS(urllib.request.BaseHandler):
        handler_order = 100

        def https_open(self, request):
            seen.append({name.lower(): value for name, value in request.header_items()})
            headers = Message()
            headers["Content-Type"] = "text/html"
            response = addinfourl(
                io.BytesIO(b'<span id="logged-in-username">demo</span>'),
                headers,
                request.full_url,
                200,
            )
            response.msg = "OK"
            return response

    builder = urllib.request.build_opener
    with patch(
        "app.source_auth.urllib.request.build_opener",
        side_effect=lambda *handlers: builder(*handlers, FakeHTTPS()),
    ):
        for _ in range(2):
            database.initialise()
            source_auth._next_request.clear()
            source_auth.fetch_source_html(
                source["id"], BASE + "/forum/tracker.php", get_adapter("rutracker")
            )
    assert len(seen) == 2
    for request in seen:
        assert request["user-agent"] == UA
        assert request["accept-language"] == "de-DE,de;q=0.9"
        assert request["sec-ch-ua-platform"] == '"macOS"'
        assert (
            "private-session" in request["cookie"]
            and "private-clearance" in request["cookie"]
        )
        assert request["accept-encoding"] == "identity"
        assert "authorization" not in request and "proxy-authorization" not in request
    # An ordinary source edit with blank account fields preserves browser context.
    client.put(
        f"/api/sources/{source['id']}",
        json={"base_url": BASE, "kind": "rutracker", "auth_mode": "cookie"},
    )
    with database.connect() as db:
        config = source_auth._read(
            db.execute(
                "SELECT * FROM source_auth WHERE source_id=?", (source["id"],)
            ).fetchone()
        )
        assert config["browser_headers"] == data["browser_headers"]
    invalid = {
        **body,
        "auth_browser_headers": {"User-Agent": "private-secret\r\nCookie: injected"},
    }
    response = client.put(f"/api/sources/{source['id']}", json=invalid)
    assert response.status_code == 422 and "private-secret" not in response.text
    with database.connect() as db:
        config = source_auth._read(
            db.execute(
                "SELECT * FROM source_auth WHERE source_id=?", (source["id"],)
            ).fetchone()
        )
        assert config["browser_headers"]["User-Agent"] == UA


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "private-secret"},
        {"Cookie": "private-secret"},
        {"Accept-Encoding": "gzip"},
        {"User-Agent": ""},
        {"User-Agent": "one", "user-agent": "two"},
    ],
)
def test_direct_api_header_input_is_restricted(client, headers):
    response = client.post(
        "/api/sources",
        json={
            "base_url": BASE,
            "kind": "rutracker",
            "auth_mode": "cookie",
            "auth_cookie": COOKIE,
            "auth_browser_headers": headers,
        },
    )
    assert response.status_code == 422
    assert (
        "private-secret" not in response.text and "private-session" not in response.text
    )
