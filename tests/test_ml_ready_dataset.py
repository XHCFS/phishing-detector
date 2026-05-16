import csv
import tempfile
import unittest
from pathlib import Path

from utils.ml_ready_dataset import build_ml_ready_rows, write_ml_ready_csv


class TestMlReadyDataset(unittest.TestCase):
    def test_merge_dedupe_cross_and_columns(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            benign = d / "benign.csv"
            phish = d / "phishing.csv"
            benign.write_text(
                "label,url,hostname,tranco_rank,stratum,benign_source,source_feed,threat_type,ip_address,ssl_enabled\n"
                "0,https://a.com/,a.com,1,d0|com,tranco_top1m,tranco_ml_benign,benign,192.0.2.1,yes\n"
                "0,https://shared-bad.test/,shared-bad.test,2,d0|com,tranco_top1m,tranco_ml_benign,benign,192.0.2.2,yes\n",
                encoding="utf-8",
            )
            phish.write_text(
                "id,label,url,domain,source_feed,threat_type,ip_address,risk_score\n"
                "99,1,https://evil.test/x,evil.test,phishtank,phishing,1.2.3.4,60\n"
                "100,1,https://shared-bad.test/,shared-bad.test,openphish,phishing,,50\n"
                "101,1,https://evil.test/x,evil.test,phishtank,phishing,1.2.3.4,60\n",
                encoding="utf-8",
            )
            rows, stats = build_ml_ready_rows(benign, phish, shuffle_seed=0)
            # same URL string in both classes → both dropped
            self.assertEqual(stats["cross_label_url_count"], 1)
            self.assertEqual(stats["output_legit"], 1)
            self.assertEqual(stats["output_phish"], 1)
            self.assertEqual(stats["output_rows"], 2)

            out = d / "out.csv"
            header = write_ml_ready_csv(out, rows, training_safe=True)
            self.assertEqual(header[0], "url")
            self.assertEqual(header[1], "label")
            self.assertEqual(header[2], "label_name")
            self.assertNotIn("id", header)
            self.assertNotIn("risk_score", header)

            with out.open(encoding="utf-8") as f:
                r = list(csv.DictReader(f))
            self.assertEqual(len(r), 2)
            labels = {int(x["label"]) for x in r}
            self.assertEqual(labels, {0, 1})
            evil = next(x for x in r if x["url"] == "https://evil.test/x")
            self.assertEqual(evil["label_name"], "phishing")
            self.assertEqual(evil.get("id", ""), "")
            self.assertNotIn("id", evil)
            legit = next(x for x in r if x["url"] == "https://a.com/")
            self.assertEqual(legit.get("source_feed"), "tranco_ml_benign")
            self.assertEqual(legit.get("threat_type"), "benign")
            self.assertEqual(legit.get("ip_address"), "192.0.2.1")
            self.assertEqual(legit.get("ssl_enabled"), "yes")


if __name__ == "__main__":
    unittest.main()
