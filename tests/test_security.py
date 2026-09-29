import unittest

from loglens.analyzer import analyze
from loglens.parser import parse_lines


def combined(ip, minute, sec, path, status):
    return (
        f"{ip} - - [28/Sep/2026:10:{minute:02d}:{sec:02d} +0000] "
        f'"GET {path} HTTP/1.1" {status} 100 "-" "curl" 0.05'
    )


class SecurityTests(unittest.TestCase):
    def analyze(self, lines):
        return analyze(parse_lines(lines)[0])["clients"]

    def test_repeated_auth_failures(self):
        lines = [combined("9.9.9.9", 1, i, "/api/login", 401) for i in range(12)]
        lines += [combined("1.1.1.1", 2, i, "/api/users", 200) for i in range(12)]
        sus = self.analyze(lines)["suspicious"]
        self.assertEqual([s["client"] for s in sus], ["9.9.9.9"])
        self.assertIn("401/403", sus[0]["patterns"][0])

    def test_probed_paths(self):
        paths = ["/.env", "/wp-admin/", "/.git/config"]
        sus = self.analyze([combined("8.8.8.8", 3, i, p, 404) for i, p in enumerate(paths)])[
            "suspicious"
        ]
        self.assertTrue(any("probed" in p for p in sus[0]["patterns"]))

    def test_high_request_rate(self):
        lines = [combined("7.7.7.7", 4, i % 60, "/api/users", 200) for i in range(70)]
        sus = self.analyze(lines)["suspicious"]
        self.assertIn("High request rate", sus[0]["patterns"][0])

    def test_normal_traffic_not_flagged(self):
        lines = [combined("1.1.1.1", 5, i, "/api/users", 200) for i in range(20)]
        self.assertEqual(self.analyze(lines)["suspicious"], [])

    def test_no_ip_data(self):
        c = self.analyze(["2026-09-28 10:00:01 INFO GET /a 200"])
        self.assertFalse(c["has_data"])
        self.assertEqual(c["suspicious"], [])

    def test_top_clients(self):
        lines = [combined("1.1.1.1", 1, i, "/a", 200) for i in range(3)]
        lines += [combined("2.2.2.2", 1, i, "/a", 500) for i in range(2)]
        c = self.analyze(lines)
        self.assertEqual(c["top"][0]["client"], "1.1.1.1")
        self.assertEqual(c["top_error_clients"][0], {"client": "2.2.2.2", "errors": 2})


if __name__ == "__main__":
    unittest.main()
