"""Smoke tests for stratified benign sampling (no large files required)."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.build_ml_dataset import (
    BENIGN_ENRICH_SOURCE_FEED,
    merge_benign_with_enriched,
    prepare_benign_rows_for_enrichment,
    sample_benign_hosts,
    fetch_phishing_rows,
    _open_enriched_with_raw,
    _dedupe_rows_by_url,
)


class TestStratifiedBenign(unittest.TestCase):
    def test_sample_benign_deterministic(self):
        lines = []
        for i in range(1, 501):
            lines.append(f"{i},example{i % 5}.com")
        tmp = Path(tempfile.mkdtemp()) / "mini.csv"
        tmp.write_text("\n".join(lines), encoding="utf-8")
        rows, meta = sample_benign_hosts(tmp, n=50, seed=123, benign_style="tranco_only")
        self.assertEqual(len(rows), 50)
        self.assertTrue(all(r["label"] == 0 for r in rows))
        self.assertTrue(all(r["url"].startswith("https://") for r in rows))
        self.assertEqual(meta["top1m_total_rows"], 500)
        self.assertGreater(len(meta["strata_allocated"]), 1)
        self.assertTrue(all(r.get("benign_source") == "tranco_top1m" for r in rows))


class TestBenignEnrichMerge(unittest.TestCase):
    def test_merge_pulls_tranco_ml_benign_row(self):
        d = Path(tempfile.mkdtemp())
        enr = d / "enr.db"
        con = sqlite3.connect(str(enr))
        con.executescript(
            """
            CREATE TABLE enriched_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                source_feed TEXT,
                threat_type TEXT,
                ip_address TEXT,
                registrar TEXT,
                first_seen TEXT
            );
            INSERT INTO enriched_threats (url, source_feed, threat_type, ip_address, registrar, first_seen)
            VALUES (
                'https://merge.example/',
                'tranco_ml_benign',
                'benign',
                '192.0.2.1',
                'Example Registrar',
                '2026-01-01'
            );
            """
        )
        con.commit()
        con.close()

        benign_rows = [
            {
                "label": 0,
                "url": "https://merge.example/",
                "hostname": "merge.example",
                "tranco_rank": 7,
                "stratum": "d0|com",
                "benign_source": "tranco_top1m",
            }
        ]
        merged, meta = merge_benign_with_enriched(enr, benign_rows)
        self.assertEqual(meta["benign_enriched_join_hits"], 1)
        self.assertEqual(merged[0]["ip_address"], "192.0.2.1")
        self.assertEqual(merged[0]["registrar"], "Example Registrar")
        self.assertEqual(merged[0]["tranco_rank"], 7)
        self.assertEqual(merged[0]["label"], 0)
        self.assertNotIn("id", merged[0])

    def test_merge_ignores_phishing_row_same_url(self):
        """Join is keyed by source_feed so a phishing row never fills benign features."""
        d = Path(tempfile.mkdtemp())
        enr = d / "enr.db"
        con = sqlite3.connect(str(enr))
        con.executescript(
            """
            CREATE TABLE enriched_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                source_feed TEXT,
                threat_type TEXT,
                ip_address TEXT,
                first_seen TEXT
            );
            INSERT INTO enriched_threats (url, source_feed, threat_type, ip_address, first_seen)
            VALUES ('https://collision.example/', 'phishtank', 'phishing', '198.51.100.2', '2026-01-01');
            """
        )
        con.commit()
        con.close()
        benign_rows = [
            {
                "label": 0,
                "url": "https://collision.example/",
                "hostname": "collision.example",
                "tranco_rank": 1,
                "stratum": "d0|com",
                "benign_source": "tranco_top1m",
            }
        ]
        merged, meta = merge_benign_with_enriched(enr, benign_rows)
        self.assertEqual(meta["benign_enriched_join_hits"], 0)
        self.assertNotIn("ip_address", merged[0])


class TestPrepareBenignMatchesSample(unittest.TestCase):
    def test_prepare_same_length_as_inline_sampling(self):
        lines = [f"{i},prep{i % 3}.test" for i in range(1, 201)]
        tmp = Path(tempfile.mkdtemp()) / "prep.csv"
        tmp.write_text("\n".join(lines), encoding="utf-8")
        a, _ = prepare_benign_rows_for_enrichment(
            tmp, n_benign=40, seed=99, benign_style="tranco_only"
        )
        b, _ = sample_benign_hosts(tmp, n=40, seed=99, benign_style="tranco_only")
        self.assertEqual(len(a), len(b))
        self.assertEqual({r["url"] for r in a}, {r["url"] for r in b})


class TestPhishingFetch(unittest.TestCase):
    def test_fetch_joins_raw_when_attached(self):
        d = Path(tempfile.mkdtemp())
        raw = d / "raw.db"
        enr = d / "enr.db"
        raw_con = sqlite3.connect(str(raw))
        raw_con.executescript(
            """
            CREATE TABLE phishtank_archival (
                phish_id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                submission_time TEXT,
                online TEXT
            );
            INSERT INTO phishtank_archival VALUES
            (1, 'http://phish.test/x', '2026-05-10T12:00:00+00:00', 'yes');
            """
        )
        raw_con.commit()
        raw_con.close()
        enr_con = sqlite3.connect(str(enr))
        enr_con.executescript(
            """
            CREATE TABLE enriched_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT,
                source_feed TEXT,
                threat_type TEXT,
                first_seen TEXT
            );
            INSERT INTO enriched_threats (url, domain, source_feed, threat_type, first_seen)
            VALUES ('http://phish.test/x', 'phish.test', 'phishtank', 'phishing', '2026-01-01');
            """
        )
        enr_con.commit()
        enr_con.close()

        con = _open_enriched_with_raw(enr, raw)
        try:
            rows, meta = fetch_phishing_rows(con, 10, seed=0, include_urlhaus=False)
        finally:
            con.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(dict(rows[0])["phishtank_submission_time"], "2026-05-10T12:00:00+00:00")
        self.assertEqual(meta["sampled_phish"], 1)

    def test_fetch_excludes_tranco_ml_benign(self):
        d = Path(tempfile.mkdtemp())
        enr = d / "enr.db"
        con = sqlite3.connect(str(enr))
        con.executescript(
            f"""
            CREATE TABLE enriched_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                source_feed TEXT,
                threat_type TEXT,
                first_seen TEXT
            );
            INSERT INTO enriched_threats (url, domain, source_feed, threat_type, first_seen) VALUES
            ('https://legit.example/', 'legit.example', 'phishtank', 'phishing', '2026-05-10'),
            ('https://benign-only.example/', 'benign-only.example', '{BENIGN_ENRICH_SOURCE_FEED}', 'benign', '2026-05-09');
            """
        )
        con.commit()
        con.close()
        con = sqlite3.connect(str(enr))
        con.row_factory = sqlite3.Row
        rows, meta = fetch_phishing_rows(con, 10, seed=0, include_urlhaus=False)
        con.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["url"], "https://legit.example/")


class TestPhishingDedupeWithinFeed(unittest.TestCase):
    def test_dedupe_keeps_one_row_per_url(self):
        d = Path(tempfile.mkdtemp())
        enr = d / "enr.db"
        enr_con = sqlite3.connect(str(enr))
        enr_con.executescript(
            """
            CREATE TABLE enriched_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                source_feed TEXT,
                threat_type TEXT,
                first_seen TEXT
            );
            INSERT INTO enriched_threats (url, domain, source_feed, threat_type, first_seen) VALUES
            ('http://dup.test/a', 'dup.test', 'phishtank', 'phishing', '2026-05-02'),
            ('http://dup.test/a', 'dup.test', 'phishtank', 'phishing', '2026-05-01'),
            ('http://other.test/b', 'other.test', 'phishtank', 'phishing', '2026-05-03');
            """
        )
        enr_con.commit()
        enr_con.close()
        con = sqlite3.connect(str(enr))
        con.row_factory = sqlite3.Row
        cur = con.execute(
            """
            SELECT * FROM enriched_threats
            WHERE source_feed = 'phishtank'
            ORDER BY datetime(first_seen) DESC
            LIMIT 10
            """
        )
        batch = cur.fetchall()
        picked = _dedupe_rows_by_url(list(batch), 2)
        self.assertEqual(len(picked), 2)
        urls = [r["url"] for r in picked]
        self.assertEqual(len(set(urls)), 2)
        con.close()


if __name__ == "__main__":
    unittest.main()
