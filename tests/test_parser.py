import unittest

from loglens.parser import parse_line, parse_lines


class ParserTests(unittest.TestCase):
    def test_app_format_with_response_time(self):
        e = parse_line("2026-09-28 10:03:45 ERROR GET /api/payment 500 812ms")
        self.assertEqual(
            (e.level, e.method, e.endpoint, e.status), ("ERROR", "GET", "/api/payment", 500)
        )
        self.assertEqual(e.response_ms, 812.0)
        self.assertEqual(e.timestamp.hour, 10)

    def test_app_format_without_response_time(self):
        e = parse_line("2026-09-28 10:00:01 INFO GET /api/users 200")
        self.assertIsNone(e.response_ms)

    def test_combined_format(self):
        line = (
            '10.0.0.5 - - [28/Sep/2026:10:00:01 +0000] "GET /api/users?page=2 HTTP/1.1" '
            '404 512 "-" "curl/8.0" 0.250'
        )
        e = parse_line(line)
        self.assertEqual(
            (e.ip, e.endpoint, e.status, e.level), ("10.0.0.5", "/api/users", 404, "WARNING")
        )
        self.assertAlmostEqual(e.response_ms, 250.0)

    def test_json_format(self):
        e = parse_line(
            '{"timestamp":"2026-09-28T10:00:00Z","method":"post","path":"/api/login",'
            '"status":201,"duration_ms":90}'
        )
        self.assertEqual(
            (e.method, e.endpoint, e.status, e.response_ms), ("POST", "/api/login", 201, 90.0)
        )

    def test_garbage_and_blank_lines(self):
        events, skipped = parse_lines(["", "not a log line", "2026-09-28 10:00:01 INFO GET /a 200"])
        self.assertEqual((len(events), skipped), (1, 1))

    def test_warn_normalised(self):
        self.assertEqual(parse_line("2026-09-28 10:00:01 WARN GET /a 429").level, "WARNING")


if __name__ == "__main__":
    unittest.main()
