import pytest

from app import database, source_auth

BASE = "https://header-form.example.invalid"
UA = "Mozilla/5.0 (Test browser)"
COOKIE = "bb_session=private-session; cf_clearance=private-clearance"
HEADERS = f"Host: header-form.example.invalid\nUser-Agent: {UA}\nCookie: {COOKIE}"


def saved_config(source_id):
    with database.connect() as db:
        row = db.execute(
            "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
        ).fetchone()
        return row["secret"], source_auth._read(row)


def test_single_field_saves_and_keeps_session_without_extraction(client):
    body = {"base_url": BASE, "kind": "rutracker", "auth_request_headers": HEADERS}
    response = client.post("/api/sources", json=body)
    assert response.status_code == 201, response.text
    source_id = response.json()["id"]
    assert response.json()["auth"]["mode"] == "cookie"
    assert UA not in response.text and "private-session" not in response.text
    secret, config = saved_config(source_id)
    assert config["cookie"] == COOKIE
    assert config["browser_headers"]["User-Agent"] == UA
    assert "request_headers" not in config
    body["auth_request_headers"] = ""
    assert client.put(f"/api/sources/{source_id}", json=body).status_code == 200
    assert saved_config(source_id)[0] == secret
    body["base_url"] = "https://other.example.invalid"
    assert client.put(f"/api/sources/{source_id}", json=body).status_code == 422
    assert client.get("/api/sources").json()[0]["base_url"] == BASE


@pytest.mark.parametrize(
    "raw,error",
    [
        ("", "Request headers are required"),
        (f"Cookie: {COOKIE}", "User-Agent is missing"),
        (f"User-Agent: {UA}", "Cookie is missing"),
        (f"User-Agent: {UA}\nCookie: bb_guid=guid", "bb_session is missing"),
        (f"User-Agent: \nCookie: {COOKIE}", "User-Agent is missing"),
    ],
)
def test_missing_values_do_not_create_or_replace_sources(client, raw, error):
    body = {"base_url": BASE, "kind": "rutracker", "auth_request_headers": raw}
    response = client.post("/api/sources", json=body)
    assert response.status_code == 422 and error in response.json()["detail"]
    assert "private-session" not in response.text
    assert client.get("/api/sources").json() == []
    good = client.post(
        "/api/sources", json={**body, "auth_request_headers": HEADERS}
    ).json()
    if raw:
        response = client.put(f"/api/sources/{good['id']}", json=body)
        assert response.status_code == 422 and error in response.json()["detail"]
        config = saved_config(good["id"])[1]
        assert (
            config["cookie"] == COOKIE and config["browser_headers"]["User-Agent"] == UA
        )


def test_legacy_session_missing_user_agent_needs_new_headers(client):
    body = {
        "base_url": BASE,
        "kind": "rutracker",
        "auth_mode": "cookie",
        "auth_cookie": COOKIE,
    }
    source = client.post("/api/sources", json=body).json()
    response = client.put(
        f"/api/sources/{source['id']}",
        json={"base_url": BASE, "kind": "rutracker", "auth_request_headers": ""},
    )
    assert response.status_code == 422
    assert (
        response.json()["detail"]
        == "Saved headers are missing User-Agent. Paste full request headers."
    )
