import io
from unittest.mock import patch

import pytest

from app import qbittorrent


def test_http_success_can_still_reject_download(client):
    qbittorrent.save_config(
        "https://client.example.invalid",
        "test-api-key",
        [{"label": "Movies", "path": "/movies"}],
    )
    response = io.BytesIO(b"Fails.")
    response.status = 200
    with patch("app.qbittorrent.urllib.request.urlopen", return_value=response):
        with pytest.raises(RuntimeError, match="rejected"):
            qbittorrent.add_magnet("magnet:?xt=urn:btih:123", "Movies")
