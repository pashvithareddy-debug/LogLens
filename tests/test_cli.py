import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from loglens.cli import main

LINES = [
    "2026-09-28 10:00:01 INFO GET /api/users 200 120ms",
    "2026-09-28 10:01:01 ERROR GET /api/orders 500 900ms",
]


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, buf.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "a.log"
        self.log.write_text("\n".join(LINES))

    def test_json_flag_outputs_only_valid_json(self):
        code, out = run([str(self.log), "--json"])
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["total_requests"], 2)
        self.assertEqual(data["meta"]["source"], str(self.log))

    def test_filters_and_exit_codes(self):
        self.assertEqual(run([str(self.log), "--status", "5xx"])[0], 0)
        self.assertEqual(run([str(self.log), "--status", "404"])[0], 1)
        self.assertEqual(run([str(Path(self.tmp.name) / "nope.log")])[0], 2)

    def test_compare_command(self):
        other = Path(self.tmp.name) / "b.log"
        other.write_text("\n".join(LINES + [LINES[1]] * 3))
        code, out = run(["compare", str(self.log), str(other)])
        self.assertEqual(code, 0)
        self.assertIn("LOG COMPARISON", out)
        code, out = run(["compare", str(self.log), str(other), "--json"])
        self.assertIn("metrics", json.loads(out))

    def test_compare_missing_file(self):
        self.assertEqual(run(["compare", str(self.log), "missing.log"])[0], 2)


if __name__ == "__main__":
    unittest.main()
