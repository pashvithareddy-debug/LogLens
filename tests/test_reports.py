import json
import tempfile
import unittest
from pathlib import Path

from loglens.analyzer import analyze
from loglens.parser import parse_lines
from loglens.reports import render_terminal, to_html, write_report

LINES = [
    "2026-09-28 10:00:01 INFO GET /api/users 200 120ms",
    "2026-09-28 10:01:01 ERROR GET /api/<b>x 500 900ms",
]


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze(parse_lines(LINES)[0])

    def test_terminal_has_sections(self):
        text = render_terminal(self.result, source="x.log")
        for section in ("SUMMARY", "ENDPOINT HEALTH", "PERFORMANCE", "SYSTEM HEALTH"):
            self.assertIn(section, text)

    def test_html_escapes_endpoints(self):
        out = to_html(self.result)
        self.assertNotIn("<b>x", out)
        self.assertIn("&lt;b&gt;x", out)

    def test_write_json_and_reject_other_extensions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.json"
            write_report(self.result, p)
            self.assertEqual(json.loads(p.read_text())["summary"]["total_requests"], 2)
            h = Path(d) / "r.html"
            write_report(self.result, h)
            self.assertIn("Diagnostic hints", h.read_text())
            with self.assertRaises(ValueError):
                write_report(self.result, Path(d) / "r.txt")


if __name__ == "__main__":
    unittest.main()
