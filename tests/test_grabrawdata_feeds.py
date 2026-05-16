"""Tests for live-feed snapshot semantics in grabrawdata."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Project root on path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.database import grabrawdata as gr


class TestPhishtankOnlineFilter(unittest.TestCase):
    def test_online_yes_only(self):
        self.assertTrue(gr._phishtank_feed_obj_is_still_online({"online": True}))
        self.assertTrue(gr._phishtank_feed_obj_is_still_online({"online": "yes"}))
        self.assertFalse(gr._phishtank_feed_obj_is_still_online({"online": False}))
        self.assertFalse(gr._phishtank_feed_obj_is_still_online({"online": "no"}))
        self.assertFalse(gr._phishtank_feed_obj_is_still_online({"online": None}))


class TestPhishtankSnapshotReplace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)

    def tearDown(self):
        self.db_path.unlink(missing_ok=True)

    def test_replaces_table_and_skips_offline(self):
        con = sqlite3.connect(str(self.db_path))
        gr.ensure_schema(con)
        con.execute(
            """INSERT INTO phishtank_archival
            (phish_id, url, phish_detail_url, submission_time, verified, verification_time,
             online, target, ip_address, cidr_block, announcing_network, rir, detail_time)
            VALUES (99999, 'http://stale.example/', '', '', 'yes', '', 'yes', '', NULL, NULL, NULL, NULL, NULL)"""
        )
        con.commit()
        con.close()

        fake = [
            {
                "phish_id": 1,
                "url": "http://a.phish/",
                "phish_detail_url": "",
                "submission_time": "2026-01-02T00:00:00+00:00",
                "verified": True,
                "verification_time": "",
                "online": True,
                "target": "t",
                "details": [],
            },
            {
                "phish_id": 2,
                "url": "http://b.phish/",
                "phish_detail_url": "",
                "submission_time": "2026-01-01T00:00:00+00:00",
                "verified": True,
                "verification_time": "",
                "online": False,
                "target": "t",
                "details": [],
            },
        ]

        con = sqlite3.connect(str(self.db_path))
        gr.ensure_schema(con)
        with patch.object(gr, "fetch_phishtank_json", return_value=fake):
            n = gr.load_phishtank_archival(con)
        con.close()

        self.assertEqual(n, 1)
        con = sqlite3.connect(str(self.db_path))
        rows = con.execute("SELECT phish_id, url, online FROM phishtank_archival ORDER BY phish_id").fetchall()
        con.close()
        self.assertEqual(rows, [(1, "http://a.phish/", "yes")])


class TestOpenPhishSnapshotReplace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)

    def tearDown(self):
        self.db_path.unlink(missing_ok=True)

    def test_replaces_table(self):
        con = sqlite3.connect(str(self.db_path))
        gr.ensure_schema(con)
        con.execute(
            "INSERT INTO openphish_feed (url, domain) VALUES ('http://old/', 'old')"
        )
        con.commit()
        con.close()

        mock_resp = MagicMock()
        mock_resp.text = "http://one/\nhttp://two/\n"

        con = sqlite3.connect(str(self.db_path))
        gr.ensure_schema(con)
        with patch.object(gr, "http_get", return_value=mock_resp):
            n = gr.load_openphish_feed(con)
        con.close()

        self.assertEqual(n, 2)
        con = sqlite3.connect(str(self.db_path))
        urls = [r[0] for r in con.execute("SELECT url FROM openphish_feed ORDER BY url").fetchall()]
        con.close()
        self.assertEqual(urls, ["http://one/", "http://two/"])


if __name__ == "__main__":
    unittest.main()
