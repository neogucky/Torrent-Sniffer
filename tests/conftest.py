from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import adapters, database, main, source_auth


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "index.sqlite")
    monkeypatch.setattr(adapters, "ADAPTER_DIR", tmp_path / "adapters")
    monkeypatch.delenv("SOURCE_SECRETS_KEY", raising=False)
    source_auth._next_request.clear()
    database.initialise()
    main.app.dependency_overrides[main.require_user] = lambda: {
        "id": 1,
        "is_admin": True,
    }
    main.app.dependency_overrides[main.require_admin] = lambda: {
        "id": 1,
        "is_admin": True,
    }
    # No lifespan: explicitly run one worker request per test.
    with patch("app.source_auth.time.sleep"):
        yield TestClient(main.app)
    main.app.dependency_overrides.clear()


@pytest.fixture
def source(client):
    return client.post(
        "/api/sources",
        json={
            "base_url": "https://source.example.invalid",
            "kind": "default",
            "min_delay_seconds": 1,
        },
    ).json()
