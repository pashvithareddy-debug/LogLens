import unittest

from loglens.filters import filter_events
from loglens.parser import parse_lines

LINES = [
    "2026-09-28 10:00:01 INFO GET /api/users 200",
    "2026-09-28 10:00:02 ERROR POST /api/payment 500",
    "2026-09-28 10:00:03 ERROR POST /api/payment/refund 502",
    "2026-09-28 10:00:04 WARNING GET /api/orders 429",
]


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.events, _ = parse_lines(LINES)

    def test_status_exact_and_class(self):
        self.assertEqual(len(filter_events(self.events, status="500")), 1)
        self.assertEqual(len(filter_events(self.events, status="5xx")), 2)

    def test_endpoint_matches_subpaths_not_prefix_strings(self):
        self.assertEqual(len(filter_events(self.events, endpoint="/api/payment")), 2)
        self.assertEqual(len(filter_events(self.events, endpoint="/api/pay")), 0)

    def test_level_and_method_case_insensitive(self):
        self.assertEqual(len(filter_events(self.events, level="error")), 2)
        self.assertEqual(len(filter_events(self.events, method="get")), 2)

    def test_combined_filters(self):
        self.assertEqual(len(filter_events(self.events, method="POST", status="5xx")), 2)

    def test_invalid_status(self):
        with self.assertRaises(ValueError):
            filter_events(self.events, status="abc")


if __name__ == "__main__":
    unittest.main()
