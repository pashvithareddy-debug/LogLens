import unittest

from loglens.analyzer import analyze
from loglens.parser import parse_lines


def build(lines):
    return parse_lines(lines)[0]


class AnalyzerTests(unittest.TestCase):
    def test_counts_and_rates(self):
        r = analyze(
            build(
                [
                    "2026-09-28 10:00:01 INFO GET /a 200 100ms",
                    "2026-09-28 10:00:02 WARNING GET /a 404 200ms",
                    "2026-09-28 10:00:03 ERROR GET /b 500 900ms",
                    "2026-09-28 11:00:03 INFO GET /b 200 300ms",
                ]
            ),
            slow_ms=500,
        )
        s = r["summary"]
        self.assertEqual((s["total_requests"], s["errors"], s["server_errors_5xx"]), (4, 2, 1))
        self.assertEqual(r["performance"]["slow_requests"], 1)
        self.assertEqual(r["performance"]["average_ms"], 375.0)
        self.assertEqual(r["performance"]["slowest"][0]["endpoint"], "/b")
        self.assertEqual(r["timeline"]["peak_traffic_hour"], "2026-09-28 10:00")

    def test_anomaly_detected_for_degraded_endpoint(self):
        lines = [f"2026-09-28 10:00:{i:02d} INFO GET /ok 200" for i in range(30)]
        lines += [f"2026-09-28 10:01:{i:02d} ERROR POST /pay 500" for i in range(4)]
        lines += [f"2026-09-28 10:02:{i:02d} INFO POST /pay 200" for i in range(4)]
        r = analyze(build(lines))
        names = [a["name"] for a in r["anomalies"] if a["scope"] == "endpoint"]
        self.assertEqual(names, ["/pay"])

    def test_no_anomaly_on_uniform_errors(self):
        lines = [f"2026-09-28 10:00:{i:02d} ERROR GET /a 500" for i in range(10)]
        lines += [f"2026-09-28 10:01:{i:02d} ERROR GET /b 500" for i in range(10)]
        self.assertEqual(analyze(build(lines))["anomalies"], [])

    def test_health_score_bounds(self):
        clean = analyze(build(["2026-09-28 10:00:01 INFO GET /a 200"] * 10))
        self.assertEqual(clean["health"]["score"], 100)
        bad = analyze(build(["2026-09-28 10:00:01 ERROR GET /a 500 2000ms"] * 10))
        self.assertLess(bad["health"]["score"], 30)
        self.assertGreaterEqual(bad["health"]["score"], 0)

    def test_no_response_time_data(self):
        r = analyze(build(["2026-09-28 10:00:01 INFO GET /a 200"]))
        self.assertFalse(r["performance"]["has_data"])


if __name__ == "__main__":
    unittest.main()
