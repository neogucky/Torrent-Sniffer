from datetime import UTC, datetime, timedelta

from app import database, main

ACCOUNT = {"username": "session-test", "password": "local-test-password"}


def real_auth(client):
    main.app.dependency_overrides.clear()
    return client


def test_separate_runtime_databases_do_not_replace_browser_sessions(
    client, tmp_path, monkeypatch
):
    real_auth(client)
    first_path = database.DB_PATH
    first = client.post("/api/auth/setup", json=ACCOUNT)
    first_cookie = main._session_cookie_name()
    assert first.status_code == 201
    assert client.get("/api/sources").status_code == 200

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "other.sqlite")
    database.initialise()
    second_cookie = main._session_cookie_name()
    assert second_cookie != first_cookie
    assert client.get("/api/auth/status").json()["user"] is None
    second = client.post("/api/auth/setup", json={**ACCOUNT, "username": "other-owner"})
    assert second.status_code == 201
    assert first_cookie in client.cookies and second_cookie in client.cookies

    monkeypatch.setattr(database, "DB_PATH", first_path)
    database.initialise()
    assert (
        client.get("/api/auth/status").json()["user"]["username"] == ACCOUNT["username"]
    )
    assert client.get("/api/sources").status_code == 200
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/status").json()["user"] is None

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "other.sqlite")
    assert client.get("/api/auth/status").json()["user"]["username"] == "other-owner"


def test_valid_legacy_session_migrates_and_logout_does_not_restore_it(client):
    real_auth(client)
    client.post("/api/auth/setup", json=ACCOUNT)
    scoped_name = main._session_cookie_name()
    token = client.cookies.get(scoped_name)
    client.cookies.clear()
    client.cookies.set(main.SESSION_COOKIE, token)
    response = client.get("/api/auth/status")
    assert response.json()["user"]["username"] == ACCOUNT["username"]
    cookie = response.headers["set-cookie"]
    assert scoped_name in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert client.cookies.get(scoped_name) == token
    database.initialise()
    assert client.get("/api/sources").status_code == 200
    client.post("/api/auth/logout")
    assert client.get("/api/sources").status_code == 401
    # Even an older browser tab retaining the old cookie cannot revive logout.
    client.cookies.set(main.SESSION_COOKIE, token)
    assert client.get("/api/auth/status").json()["user"] is None


def test_expired_or_invalid_sessions_do_not_migrate(client):
    real_auth(client)
    client.post("/api/auth/setup", json=ACCOUNT)
    name = main._session_cookie_name()
    token = client.cookies.get(name)
    with database.connect() as db:
        db.execute(
            "UPDATE sessions SET expires_at=?",
            (
                (datetime.now(UTC) - timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
            ),
        )
    client.cookies.clear()
    client.cookies.set(main.SESSION_COOKIE, token)
    response = client.get("/api/auth/status")
    assert response.json()["user"] is None
    assert "set-cookie" not in response.headers
    assert client.get("/api/sources").status_code == 401


def test_source_refusal_keeps_application_session(client, monkeypatch):
    real_auth(client)
    client.post("/api/auth/setup", json=ACCOUNT)
    source = client.post(
        "/api/sources",
        json={
            "base_url": "https://login-test.example.invalid",
            "kind": "rutracker",
            "auth_mode": "password",
            "auth_username": "demo",
            "auth_password": "demo-password",
        },
    ).json()

    def refused(*args):
        raise RuntimeError("Source returned HTTP 403 while opening the login page")

    monkeypatch.setattr(main, "fetch_source_html", refused)
    response = client.post(f"/api/sources/{source['id']}/login")
    assert response.status_code == 502
    assert "HTTP 403" in response.json()["detail"]
    assert "set-cookie" not in response.headers
    assert (
        client.get("/api/auth/status").json()["user"]["username"] == ACCOUNT["username"]
    )
    assert len(client.get("/api/sources").json()) == 1
