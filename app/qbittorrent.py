from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from typing import Any

from .database import connect


def public_config() -> dict[str, Any]:
    with connect() as db:
        config = db.execute(
            "SELECT base_url, locations_json FROM qbittorrent_config WHERE id=1"
        ).fetchone()
    if not config:
        return {"configured": False, "locations": []}
    return {
        "configured": True,
        "base_url": config["base_url"],
        "locations": json.loads(config["locations_json"]),
    }


def save_config(
    base_url: str, api_key: str | None, locations: list[dict[str, str]]
) -> None:
    with connect() as db:
        existing = db.execute(
            "SELECT api_key FROM qbittorrent_config WHERE id=1"
        ).fetchone()
        secret = (
            api_key.strip() if api_key else (existing["api_key"] if existing else "")
        )
        if not secret:
            raise ValueError(
                "An API key is required when first configuring qBittorrent"
            )
        db.execute(
            """INSERT INTO qbittorrent_config(id, base_url, api_key, locations_json, updated_at)
               VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url, api_key=excluded.api_key,
                 locations_json=excluded.locations_json, updated_at=CURRENT_TIMESTAMP""",
            (base_url.rstrip("/"), secret, json.dumps(locations)),
        )


def clear_config() -> None:
    with connect() as db:
        db.execute("DELETE FROM qbittorrent_config WHERE id=1")


def add_magnet(magnet_link: str, location_label: str) -> None:
    with connect() as db:
        config = db.execute("SELECT * FROM qbittorrent_config WHERE id=1").fetchone()
    if not config:
        raise ValueError("qBittorrent integration is not configured")
    locations = json.loads(config["locations_json"])
    location = next(
        (item for item in locations if item["label"] == location_label), None
    )
    if not location:
        raise ValueError("Unknown qBittorrent file location")
    body, content_type = _multipart({"urls": magnet_link, "savepath": location["path"]})
    request = urllib.request.Request(
        f"{config['base_url']}/api/v2/torrents/add",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {config['api_key']}",
            "Content-Type": content_type,
            "Accept": "text/plain",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            if response.status not in {200, 201}:
                raise RuntimeError(f"qBittorrent returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"qBittorrent returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach qBittorrent: {error.reason}") from error


def _multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = f"----TorrentSniffer{secrets.token_hex(12)}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
