import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .compare import compare_results, render_comparison
from .filters import filter_events
from .parser import parse_file
from .reports import render_terminal, to_json, write_report


def build_parser():
    p = argparse.ArgumentParser(
        prog="loglens",
        description="Log intelligence CLI: traffic, errors, endpoint health, performance, "
        "anomalies, clients. Use `loglens compare A.log B.log` to compare two logs.",
    )
    p.add_argument(
        "file", help="Path to a log file (app-style, Apache/Nginx combined, or JSON lines)"
    )
    p.add_argument("--status", help="Only this status code or class, e.g. 500 or 5xx")
    p.add_argument("--endpoint", help="Only this endpoint (matches sub-paths too)")
    p.add_argument("--level", help="Only this log level, e.g. ERROR")
    p.add_argument("--method", help="Only this HTTP method, e.g. POST")
    p.add_argument(
        "--slow-ms", type=float, default=500.0, help="Slow-request threshold in ms (default 500)"
    )
    p.add_argument("--top", type=int, default=5, help="Rows in top-N lists (default 5)")
    p.add_argument("--json", action="store_true", help="Print the full analysis as JSON to stdout")
    p.add_argument("--report", metavar="PATH", help="Write a .json or .html report")
    p.add_argument("--version", action="version", version=f"loglens {__version__}")
    return p


def build_compare_parser():
    p = argparse.ArgumentParser(prog="loglens compare", description="Compare two log files.")
    p.add_argument("before", help="Baseline log file (e.g. yesterday.log)")
    p.add_argument("after", help="Log file to compare against the baseline (e.g. today.log)")
    p.add_argument("--slow-ms", type=float, default=500.0)
    p.add_argument("--json", action="store_true", help="Print the comparison as JSON")
    return p


def _analyze_file(path, slow_ms, top=5, **filters):
    events, skipped = parse_file(path)
    events = filter_events(events, **filters)
    if not events:
        return None, skipped
    return analyze(events, slow_ms=slow_ms, top=top), skipped


def _compare_main(argv) -> int:
    args = build_compare_parser().parse_args(argv)
    results = []
    for path in (args.before, args.after):
        if not Path(path).is_file():
            print(f"loglens: cannot read {path!r}", file=sys.stderr)
            return 2
        result, _ = _analyze_file(path, args.slow_ms)
        if result is None:
            print(f"loglens: no parseable requests in {path!r}", file=sys.stderr)
            return 1
        results.append(result)
    comparison = compare_results(*results)
    if args.json:
        import json

        print(json.dumps(comparison, indent=2))
    else:
        print(render_comparison(comparison, Path(args.before).name, Path(args.after).name))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "compare":
        return _compare_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.report and Path(args.report).suffix.lower() not in (".json", ".html", ".htm"):
        parser.error("--report path must end in .json or .html")
    if not Path(args.file).is_file():
        print(f"loglens: cannot read {args.file!r}", file=sys.stderr)
        return 2

    filters = {
        k: v
        for k, v in (
            ("status", args.status),
            ("endpoint", args.endpoint),
            ("level", args.level),
            ("method", args.method),
        )
        if v
    }
    try:
        result, skipped = _analyze_file(args.file, args.slow_ms, args.top, **filters)
    except ValueError as exc:
        parser.error(str(exc))

    if result is None:
        print(
            f"loglens: no matching requests found ({skipped} unparseable line(s) skipped).",
            file=sys.stderr,
        )
        return 1

    result["meta"] = {"source": args.file, "filters": filters, "skipped_lines": skipped}
    if args.json:
        print(to_json(result))
    else:
        print(render_terminal(result, source=args.file, filters=filters, skipped=skipped))
    if args.report:
        write_report(result, args.report, source=args.file)
        if not args.json:
            print(f"\nReport written to {args.report}")
    return 0
