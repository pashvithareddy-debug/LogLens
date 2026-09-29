import unittest

from loglens.analyzer import analyze
from loglens.parser import parse_lines
from loglens.stats import latency_stats, percentile


class StatsTests(unittest.TestCase):
    def test_percentile(self):
        vals = list(range(1, 101))
        self.assertAlmostEqual(percentile(vals, 50), 50.5)
        self.assertAlmostEqual(percentile(vals, 95), 95.05)
        self.assertIsNone(percentile([], 50))

    def test_latency_stats_empty(self):
        self.assertEqual(latency_stats([])["p95_ms"], None)

    def test_analyzer_exposes_percentiles(self):
        events, _ = parse_lines(
            [f"2026-09-28 10:00:{i:02d} INFO GET /a 200 {i * 10}ms" for i in range(1, 11)]
        )
        p = analyze(events)["performance"]
        self.assertEqual(p["p50_ms"], 55.0)
        self.assertGreater(p["p99_ms"], p["p95_ms"])


class HintTests(unittest.TestCase):
    def test_combined_errors_and_latency_hint(self):
        lines = [f"2026-09-28 10:00:{i:02d} INFO GET /fast 200 50ms" for i in range(20)]
        lines += [f"2026-09-28 10:01:{i:02d} ERROR POST /pay 500 1500ms" for i in range(4)]
        lines += [f"2026-09-28 10:02:{i:02d} INFO POST /pay 200 1400ms" for i in range(4)]
        hints = analyze(parse_lines(lines)[0])["hints"]
        self.assertEqual(hints[0]["endpoint"], "/pay")
        self.assertIn("latency", hints[0]["findings"][0]["possible_issue"].lower())

    def test_auth_failure_hint(self):
        lines = [f"2026-09-28 10:00:{i:02d} WARNING POST /login 401" for i in range(6)]
        lines += [f"2026-09-28 10:01:{i:02d} INFO POST /login 200" for i in range(4)]
        hints = analyze(parse_lines(lines)[0])["hints"]
        issues = " ".join(f["possible_issue"] for f in hints[0]["findings"])
        self.assertIn("401/403", issues)

    def test_healthy_endpoint_has_no_hint(self):
        lines = [f"2026-09-28 10:00:{i:02d} INFO GET /a 200 40ms" for i in range(10)]
        self.assertEqual(analyze(parse_lines(lines)[0])["hints"], [])


if __name__ == "__main__":
    unittest.main()
