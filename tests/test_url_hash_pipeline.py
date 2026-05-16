"""URL-hash model: augment loader, small fit smoke, bundle sanity (optional model on disk)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from utils.sanity_url_hash_model import run_sanity
from utils.train_url_hash_model import build_pipeline, canonicalize_url_for_model, load_augment_benign_urls

REPO = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = REPO / "data" / "ml_dataset" / "models" / "url_char_lr.joblib"


class TestAugmentLoader(unittest.TestCase):
    def test_dedupe_and_comments(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("# c\n")
            f.write("https://A.COM/x\r\n")
            f.write("https://a.com/x\n")
            f.write("\n")
            f.write("https://b.com/\n")
            path = Path(f.name)
        try:
            u = load_augment_benign_urls(path)
            self.assertEqual(u, ["https://a.com/x", "https://b.com/"])
        finally:
            path.unlink(missing_ok=True)


class TestCanonicalize(unittest.TestCase):
    def test_http_upgraded(self) -> None:
        self.assertEqual(
            canonicalize_url_for_model("HTTP://Ex.Org/path"),
            "https://ex.org/path",
        )


class TestBuildPipelineSmoke(unittest.TestCase):
    def test_fit_predict_two_class(self) -> None:
        rng = np.random.default_rng(0)
        n = 80
        urls = []
        y = []
        for i in range(n // 2):
            urls.append(f"https://benign{i}.example.com/")
            y.append(0)
        for i in range(n // 2):
            urls.append(f"https://evil-phish-{i}.invoice-login.ru/pay?x=1")
            y.append(1)
        order = rng.permutation(n)
        urls = [urls[i] for i in order]
        y = np.array([y[i] for i in order], dtype=np.int64)
        X = pd.Series(urls, dtype=str)

        pipe = build_pipeline(n_features_bits=12, ngram_lo=2, ngram_hi=4, C=2.0, seed=0)
        pipe.fit(X, y)
        proba = pipe.predict_proba(X)[:, 1]
        self.assertGreater(float(proba.mean()), 0.0)
        self.assertLess(float(proba.mean()), 1.0)
        pred = (proba >= 0.5).astype(int)
        self.assertGreaterEqual((pred == y).mean(), 0.75)

    def test_http_https_identical_proba(self) -> None:
        pipe = build_pipeline(n_features_bits=12, ngram_lo=2, ngram_hi=4, C=2.0, seed=0)
        X = pd.Series(
            [
                "https://same.example.com/a?x=1",
                "http://evil-phish.example.com/invoice",
            ],
            dtype=str,
        )
        y = np.array([0, 1], dtype=np.int64)
        pipe.fit(X, y)
        pair = np.array(["https://dup.test/foo", "http://dup.test/foo"], dtype=object)
        p = pipe.predict_proba(pair)[:, 1]
        self.assertAlmostEqual(float(p[0]), float(p[1]), places=6)


@unittest.skipUnless(DEFAULT_MODEL.exists(), "trained url_char_lr.joblib not present")
class TestLoadedModelPredict(unittest.TestCase):
    def test_probabilities_in_range(self) -> None:
        import joblib

        pipe = joblib.load(DEFAULT_MODEL)["pipeline"]
        urls = ["https://example.com/", "https://yeefish0.github.io/steam_login_auth"]
        p = pipe.predict_proba(np.array([u.lower() for u in urls]))[:, 1]
        self.assertTrue(np.all((p >= 0) & (p <= 1)))
        self.assertGreater(float(p[1]), 0.9)
        self.assertLess(float(p[0]), 0.5)


@unittest.skipUnless(DEFAULT_MODEL.exists(), "trained url_char_lr.joblib not present")
class TestSanityGoldenIntegration(unittest.TestCase):
    def test_run_sanity_passes(self) -> None:
        rc = run_sanity(
            model_path=DEFAULT_MODEL,
            tranco_csv=REPO / "top-1m.csv",
            tranco_n=2000,
            max_tranco_fpr=0.05,
            openphish_file=None,
            openphish_fetch=False,
            min_openphish_recall=0.0,
            golden_benign_max_p=0.55,
            golden_phish_min_p=0.82,
        )
        self.assertEqual(rc, 0)


@unittest.skipUnless(
    (Path(__file__).resolve().parents[1] / "top-1m.csv").exists(),
    "top-1m.csv not present",
)
class TestDeployStressHelpers(unittest.TestCase):
    def test_load_tranco_apex(self) -> None:
        from utils.deploy_stress_sanity import DEFAULT_TRANCO, load_tranco_apex

        urls = load_tranco_apex(100, DEFAULT_TRANCO)
        self.assertGreater(len(urls), 50)
        self.assertTrue(all(u.startswith("https://") and u.endswith("/") for u in urls))


    def test_ablation_unique_strings(self) -> None:
        from utils.explain_url_hash_model import ablation_variants

        url = "https://ex.org/a/b#frag"
        rows = ablation_variants(url)
        strings = [v for _, v in rows]
        self.assertEqual(len(strings), len(set(strings)))


if __name__ == "__main__":
    unittest.main()
