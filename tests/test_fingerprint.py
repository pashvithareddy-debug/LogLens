import unittest

from loglens.analyzer import analyze
from loglens.fingerprint import normalize_endpoint
from loglens.parser import parse_lines


class FingerprintTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_endpoint("/api/orders/1041"), "/api/orders/:id")
        self.assertEqual(
            normalize_endpoint("/u/123e4567-e89b-12d3-a456-426614174000/x"), "/u/:id/x"
        )
        self.assertEqual(normalize_endpoint("/api/v2/users"), "/api/v2/users")

    def test_groups_merge_ids_and_track_first_last_seen(self):
        events, _ = parse_lines(
            [
                "2026-09-28 10:04:00 ERROR GET /api/orders/1 500",
                "2026-09-28 12:47:00 ERROR GET /api/orders/2 500",
                "2026-09-28 11:00:00 ERROR GET /api/orders/3 500",
                "2026-09-28 11:01:00 ERROR POST /api/pay 502",
            ]
        )
        groups = analyze(events)["error_intelligence"]["error_groups"]
        self.assertEqual(groups[0]["endpoint"], "/api/orders/:id")
        self.assertEqual(groups[0]["count"], 3)
        self.assertEqual(groups[0]["first_seen"], "2026-09-28T10:04:00")
        self.assertEqual(groups[0]["last_seen"], "2026-09-28T12:47:00")
        self.assertEqual(len(groups), 2)


if __name__ == "__main__":
    unittest.main()
