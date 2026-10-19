import pytest

from app import database, source_auth
from app.browser_headers import normalise_request_headers

BASE = "https://clipboard.example.invalid"
UA = "Mozilla/5.0 (Example Browser: unchanged) Test/123.0"
COOKIE = "bb_session=demo-session; cf_clearance=demo-clearance; bb_data=a%3A1%3B; padded=abc=="
PAIRS = [
    (":authority", "clipboard.example.invalid"),
    (":method", "GET"),
    (":path", "/forum/tracker.php?example=1"),
    (":scheme", "https"),
    ("Accept", 'text/html; note="Cookie: unchanged"'),
    ("Accept-Language", "en-GB,en;q=0.9"),
    ("Cookie", COOKIE),
    ("Referer", BASE + "/forum/index.php"),
    ("Sec-CH-UA", '"User-Agent: Example";v="123"'),
    ("Sec-Fetch-Mode", "navigate"),
    ("User-Agent", UA),
]
ROWS = [f"{name}: {value}" for name, value in PAIRS]
CELLS = [cell for pair in PAIRS for cell in pair]
COPIES = {
    "alternating_lines": "\n".join(CELLS),
    "alternating_with_blank_rows": "\n\n".join(CELLS),
    "labels_with_colons": "\n".join(f"{name}:\n{value}" for name, value in PAIRS),
    "tabbed_rows": "\n".join(f"{name}\t{value}" for name, value in PAIRS),
    "tabbed_cells": "\t".join(CELLS),
    "tabbed_headers": "\t".join(ROWS),
    "flattened_headers": " ".join(ROWS),
    "literal_line_breaks": "\\n".join(ROWS),
    "literal_windows_line_breaks": "\\r\\n".join(ROWS),
    "carriage_returns": "\r".join(ROWS),
    "unicode_line_breaks": "\ufeff" + "\u2028".join(ROWS),
    "unicode_paragraph_breaks": "\u2029".join(CELLS),
    "nonbreaking_separator_spaces": "\n".join(
        f"{name}:\u00a0{value}" for name, value in PAIRS
    ),
}


@pytest.mark.parametrize("copy", COPIES.values(), ids=COPIES.keys())
def test_browser_clipboard_formats_save_the_same_values(client, copy):
    response = client.post(
        "/api/sources",
        json={"base_url": BASE, "kind": "rutracker", "auth_request_headers": copy},
    )
    assert response.status_code == 201, response.text
    source_id = response.json()["id"]
    with database.connect() as db:
        config = source_auth._read(
            db.execute(
                "SELECT * FROM source_auth WHERE source_id=?", (source_id,)
            ).fetchone()
        )
    assert config["cookie"] == COOKIE
    assert config["browser_headers"]["User-Agent"] == UA
    assert config["browser_headers"]["Accept"] == 'text/html; note="Cookie: unchanged"'
    assert config["browser_headers"]["Sec-CH-UA"] == '"User-Agent: Example";v="123"'
    assert "Referer" not in config["browser_headers"]
    assert normalise_request_headers(
        normalise_request_headers(copy)
    ) == normalise_request_headers(copy)


def test_flat_request_line_and_url_colons_are_preserved(client):
    raw = f"GET /forum/tracker.php HTTP/2 Host: clipboard.example.invalid User-Agent: {UA} Referer: {BASE}/forum/ Cookie: {COOKIE}"
    response = client.post(
        "/api/sources",
        json={"base_url": BASE, "kind": "rutracker", "auth_request_headers": raw},
    )
    assert response.status_code == 201, response.text
    normalized = normalise_request_headers(raw)
    assert normalized.startswith("GET /forum/tracker.php HTTP/2\nHost:")
    assert f"Referer: {BASE}/forum/" in normalized


@pytest.mark.parametrize(
    "raw,expected",
    [
        (f"Cookie\n{COOKIE}\nUser-Agent", "User-Agent is missing"),
        (f"User-Agent:\nCookie:\n{COOKIE}", "User-Agent is missing"),
        (f"User-Agent\n{UA}\nCookie", "Cookie is missing"),
        (f"User-Agent\t{UA}\nCookie\tbb_guid=demo", "bb_session is missing"),
        (
            f"User-Agent\n{UA}\nCookie\n{COOKIE}\nHost\ndifferent.example.invalid",
            "different source",
        ),
        (
            f"User-Agent\n{UA}\nCookie\n{COOKIE}\nUser-Agent\nprivate-secret",
            "more than once",
        ),
        (
            f"User-Agent\n{UA}\nCookie\n{COOKIE}\nSet-Cookie\nprivate-secret",
            "response headers",
        ),
        (
            f"GET / HTTP/1.1\nUser-Agent\n{UA}\nCookie\n{COOKIE}\n\nprivate-secret",
            "request body",
        ),
    ],
)
def test_normalization_preserves_missing_values_and_safety_checks(
    client, raw, expected
):
    response = client.post(
        "/api/sources",
        json={"base_url": BASE, "kind": "rutracker", "auth_request_headers": raw},
    )
    assert response.status_code == 422, response.text
    assert expected in response.json()["detail"]
    assert "private-secret" not in response.text and "demo-session" not in response.text
    assert client.get("/api/sources").json() == []
