"""Tests for URL-string-only feature extraction."""
from __future__ import annotations

import unittest

from utils.url_only_features import extract_url_only_features


class TestUrlOnlyFeatures(unittest.TestCase):
    def test_https_and_lengths(self) -> None:
        f = extract_url_only_features("https://sub.example.com/a/b?x=1")
        self.assertEqual(f["scheme_https"], 1.0)
        self.assertGreater(f["url_char_len"], 10.0)
        self.assertGreaterEqual(f["n_path_segments"], 1.0)
        self.assertGreaterEqual(f["n_query_keys"], 1.0)

    def test_ip_host(self) -> None:
        f = extract_url_only_features("http://192.0.2.1/path")
        self.assertEqual(f["host_is_ipv4"], 1.0)

    def test_empty_url(self) -> None:
        f = extract_url_only_features("")
        self.assertEqual(f["url_char_len"], 0.0)


if __name__ == "__main__":
    unittest.main()
