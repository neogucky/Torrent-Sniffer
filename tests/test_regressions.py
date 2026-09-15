import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import Request, Response

from app import database, main
from app.crawler import extraction_diagnostics, parse_results


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.adapter = {"result": {"fields": {
            "title": {"link_href_contains": "/item/"},
            "details_url": {"link_href_contains": "/item/", "value": "href", "as": "url"},
            "size": {"alternatives": [
                {"cell_class_contains": "metadata", "text_regex": r"Size\s+([0-9.,]+\s*[KMGT]?i?B)"},
                {"row_cell_count": 5, "fallback_index": 1},
            ]},
            "seeders": {"alternatives": [
                {"row_cell_count": 5, "fallback_index": 2, "as": "integer"},
                {"row_cell_count": 3, "fallback_index": 1, "as": "integer"},
            ]},
            "uploader": {"link_href_contains": "/author/"},
        }}}

    def test_alternative_layouts(self):
        rows = [
            '<tr><td><a href="/item/1">Example</a><span class="metadata">Size 1,5 GiB, Other</span></td><td>7</td><td><a href="/author/a">Alice</a></td></tr>',
            '<tr><td><a href="/item/1">Example</a><a href="/author/a"><img></a></td><td>1,5&nbsp;GiB</td><td>7</td><td>0</td><td><a href="/author/a">Alice</a></td></tr>',
        ]
        for html in rows:
            with self.subTest(html=html):
                results = parse_results(html, "https://example.org", self.adapter)
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0].size_bytes, 1610612736)
                self.assertEqual(results[0].seeders, 7)
                self.assertEqual(results[0].uploader, "Alice")
                self.assertIsNone(extraction_diagnostics(results, self.adapter))

    def test_missing_fields_are_reported(self):
        results = parse_results('<tr><td><a href="/item/1">Example</a></td></tr>', "https://example.org", self.adapter)
        self.assertIsNone(results[0].size)
        self.assertIn("size: 1/1 missing", extraction_diagnostics(results, self.adapter))
        self.assertIn("No result rows matched", extraction_diagnostics([], self.adapter))


class AuthPersistenceTests(unittest.TestCase):
    def test_account_and_session_survive_reinitialisation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(database, "DB_PATH", Path(directory) / "test.sqlite"), patch("app.adapters.ensure_default_adapter"):
            database.initialise()
            response = Response()
            credentials = main.Credentials(username="testowner", password="test-password")
            user = main.setup_owner(credentials, response)
            cookie = response.headers["set-cookie"].split(";", 1)[0]
            self.assertIn("Max-Age=1209600", response.headers["set-cookie"])
            database.initialise()
            request = Request({"type": "http", "headers": [(b"cookie", cookie.encode())]})
            self.assertEqual(main.auth_status(request), {"needs_setup": False, "user": user})
            anonymous = Request({"type": "http", "headers": []})
            self.assertEqual(main.auth_status(anonymous), {"needs_setup": False, "user": None})
            main.logout(request, Response())
            self.assertIsNone(main.auth_status(request)["user"])
            self.assertEqual(main.login(credentials, Response()), user)


if __name__ == "__main__":
    unittest.main()
