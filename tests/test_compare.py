import unittest

from loglens.analyzer import analyze
from loglens.compare import compare_results, render_comparison
from loglens.parser import parse_lines


def result(n_ok, n_err, ms):
    lines = [f"2026-09-28 10:00:{i % 60:02d} INFO GET /api/a 200 {ms}ms" for i in range(n_ok)]
    lines += [f"2026-09-28 10:01:{i % 60:02d} ERROR GET /api/a 500 {ms}ms" for i in range(n_err)]
    return analyze(parse_lines(lines)[0])


class CompareTests(unittest.TestCase):
    def test_flags_regression(self):
        c = compare_results(result(98, 2, 100), result(90, 10, 200))
        messages = [n["message"] for n in c["notes"] if n["level"] == "warning"]
        self.assertTrue(any("Error rate increased" in m for m in messages))
        self.assertTrue(any("Avg latency increased" in m for m in messages))
        self.assertEqual(c["endpoint_regressions"][0]["endpoint"], "/api/a")

    def test_flags_improvement(self):
        c = compare_results(result(80, 20, 200), result(98, 2, 100))
        self.assertTrue(any(n["level"] == "improvement" for n in c["notes"]))

    def test_identical_logs_have_no_notes(self):
        c = compare_results(result(95, 5, 100), result(95, 5, 100))
        self.assertEqual(c["notes"], [])
        self.assertIn("No significant changes", render_comparison(c, "a", "b"))

    def test_zero_baseline_errors(self):
        c = compare_results(result(100, 0, 100), result(90, 10, 100))
        self.assertTrue(any("rose from 0" in n["message"] for n in c["notes"]))


if __name__ == "__main__":
    unittest.main()
