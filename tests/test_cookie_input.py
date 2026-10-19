from email.message import Message
from unittest.mock import patch

import pytest

from app import database, main, source_auth


@pytest.mark.parametrize(
    "header,count",
    [
        ("bb_session=demo-session", 1),
        (" Cookie: bb_guid=guid; bb_session=session-token; bb_data=a%3A1%3B ", 3),
        ("cookie: bb_session=abc==; optional=", 2),
        ('bb_session="quoted-token"; preference=enabled;', 2),
    ],
)
def test_cookie_check_accepts_complete_header_or_single_named_cookie(
    client, header, count
):
    response = client.post("/api/source-auth/validate-cookie", json={"cookie": header})
    assert response.status_code == 200, response.text
    assert response.json()["cookie_count"] == count
    assert response.json()["session_cookie_present"] is True
    assert "session is accepted" in response.json()["message"]
    assert "demo-session" not in response.text and "session-token" not in response.text
    assert "quoted-token" not in response.text


@pytest.mark.parametrize(
    "cookie,expected",
    [
        ("just-a-session-value", "name and value"),
        ("bb_guid=guid", "bb_session is missing"),
        ("bb_session=", "missing or empty"),
        ("Cookie: bb_session=...", "Replace the example"),
        (
            "Set-Cookie: bb_session=private-secret; Path=/; HttpOnly",
            "Set-Cookie response",
        ),
        ("bb_session=private-secret; Path=/; Secure", "Cookie attributes"),
        (
            "bb_session=private-secret\nAuthorization: Bearer private-secret",
            "single Cookie",
        ),
        ('{"bb_session": "private-secret"}', "cookie export"),
        ("bb_session\tprivate-secret\t.example.invalid\t/", "single Cookie"),
        (
            "curl https://example.invalid -H 'Cookie: bb_session=private-secret'",
            "only the Cookie",
        ),
        ("bb_session=a; bb_session=b", "repeats a cookie name"),
        ("bb_session=private-secret, other=abc", "unsupported characters"),
        ("bb_session=private-secret with spaces", "unsupported characters"),
        ("bb_session=private-secret💡", "single Cookie"),
        ('bb_session="unclosed', "unsupported characters"),
    ],
)
def test_cookie_check_rejects_wrong_copy_without_echoing_credentials(
    client, cookie, expected
):
    response = client.post("/api/source-auth/validate-cookie", json={"cookie": cookie})
    assert response.status_code == 422
    assert expected in response.json()["detail"]
    assert "private-secret" not in response.text


def test_cookie_check_never_stores_or_sends_cookie(client):
    with (
        patch("app.source_auth.urllib.request.urlopen") as plain,
        patch("app.source_auth.urllib.request.build_opener") as opener,
    ):
        response = client.post(
            "/api/source-auth/validate-cookie",
            json={"cookie": "Cookie: bb_session=local-check-only"},
        )
    assert response.status_code == 200
    plain.assert_not_called()
    opener.assert_not_called()
    with database.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM source_auth").fetchone()[0] == 0


def test_cookie_check_requires_admin_and_redacts_schema_errors(client):
    response = client.post(
        "/api/source-auth/validate-cookie", json={"cookie": "private-secret" * 2000}
    )
    assert response.status_code == 422 and "private-secret" not in response.text
    main.app.dependency_overrides.pop(main.require_admin)
    main.app.dependency_overrides[main.require_user] = lambda: {
        "id": 2,
        "is_admin": False,
    }
    assert (
        client.post(
            "/api/source-auth/validate-cookie", json={"cookie": "bb_session=demo"}
        ).status_code
        == 403
    )
    main.app.dependency_overrides.clear()
    assert (
        client.post(
            "/api/source-auth/validate-cookie", json={"cookie": "bb_session=demo"}
        ).status_code
        == 401
    )


def test_cookie_save_uses_same_validator_and_normalizes_header(client):
    body = {
        "base_url": "https://cookie-check.example.invalid",
        "kind": "rutracker",
        "auth_mode": "cookie",
        "auth_cookie": "Cookie: bb_guid=guid; bb_session=real-test-value",
    }
    response = client.post("/api/sources", json=body)
    assert response.status_code == 201, response.text
    assert "real-test-value" not in response.text
    source_id = response.json()["id"]
    with database.connect() as db:
        row = db.execute(
            "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
        ).fetchone()
        assert (
            source_auth._read(row)["cookie"]
            == "bb_guid=guid; bb_session=real-test-value"
        )
    body["auth_cookie"] = "bare-value"
    assert client.put(f"/api/sources/{source_id}", json=body).status_code == 422
    # Invalid replacement rolls back, preserving the saved browser session.
    with database.connect() as db:
        row = db.execute(
            "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
        ).fetchone()
        assert "real-test-value" in source_auth._read(row)["cookie"]


@pytest.mark.parametrize(
    "header,value,expected",
    [
        (
            "X-Mitmproxy-Blocked-Reason",
            "ROBOTS_DENIED",
            "network proxy denial (ROBOTS_DENIED)",
        ),
        (
            "X-Mitmproxy-Blocked-Reason",
            "PRIVATE-secret-reason",
            "network proxy denial (an access policy)",
        ),
        ("CF-Mitigated", "challenge", "browser-verification challenge"),
    ],
)
def test_403_diagnostics_classify_explicit_denials_without_exposing_raw_headers(
    header, value, expected
):
    headers = Message()
    headers[header] = value
    headers["Set-Cookie"] = "bb_session=private-cookie"
    error = source_auth.SourceHTTPError(403, headers, "opening the login page")
    assert expected in str(error)
    assert "PRIVATE-secret-reason" not in str(error)
    assert "private-cookie" not in str(error)
