"""Parses app-style, Apache/Nginx combined, and JSON-lines logs into Events.

Format is detected per line, so mixed files work.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .models import Event

# 2026-09-28 10:00:01 INFO GET /api/users 200 [123ms]
APP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\s+"
    r"(?P<level>[A-Za-z]+)\s+(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+"
    r"(?P<status>\d{3})(?!\d)(?:\s+(?P<rt>\d+(?:\.\d+)?)\s*ms)?"
)

# Apache/Nginx "combined". A trailing number is read as request time in seconds
# (e.g. nginx $request_time).
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?:\d+|-)(?: "[^"]*" "[^"]*")?(?: (?P<rt>\d+(?:\.\d+)?))?\s*$'
)


def _derive_level(level: Optional[str], status: int) -> str:
    if level:
        level = level.upper()
        return "WARNING" if level == "WARN" else level
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


def _clean_path(path: str) -> str:
    return path.split("?", 1)[0] or "/"


def _parse_ts(value) -> Optional[datetime]:
    """Parse a timestamp; timezone info is dropped so all events stay comparable."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)
        text = str(value).strip()
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=None)
            except ValueError:
                pass
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, OSError, OverflowError):
        return None


def _first(data: dict, *keys):
    for key in keys:
        if data.get(key) not in (None, ""):
            return data[key]
    return None


def _parse_json(line: str) -> Optional[Event]:
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        status = int(_first(data, "status", "status_code", "code"))
    except (TypeError, ValueError):
        return None
    path = _first(data, "path", "endpoint", "url", "uri")
    method = _first(data, "method", "verb")
    if not path or not method:
        return None
    rt = _first(data, "response_time_ms", "duration_ms", "latency_ms", "response_time")
    try:
        rt = float(rt) if rt is not None else None
    except (TypeError, ValueError):
        rt = None
    return Event(
        timestamp=_parse_ts(_first(data, "timestamp", "time", "ts", "@timestamp")),
        level=_derive_level(_first(data, "level", "severity"), status),
        method=str(method).upper(),
        endpoint=_clean_path(str(path)),
        status=status,
        ip=_first(data, "ip", "remote_addr", "client_ip"),
        response_ms=rt,
    )


def parse_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        return _parse_json(line)

    m = APP_RE.match(line)
    if m:
        status = int(m["status"])
        return Event(
            timestamp=_parse_ts(m["ts"]),
            level=_derive_level(m["level"], status),
            method=m["method"],
            endpoint=_clean_path(m["path"]),
            status=status,
            response_ms=float(m["rt"]) if m["rt"] else None,
        )

    m = COMBINED_RE.match(line)
    if m:
        status = int(m["status"])
        return Event(
            timestamp=_parse_ts(m["ts"]),
            level=_derive_level(None, status),
            method=m["method"],
            endpoint=_clean_path(m["path"]),
            status=status,
            ip=m["ip"],
            response_ms=float(m["rt"]) * 1000 if m["rt"] else None,
        )
    return None


def parse_lines(lines: Iterable[str]) -> Tuple[List[Event], int]:
    """Returns (events, number_of_non_empty_lines_that_could_not_be_parsed)."""
    events, skipped = [], 0
    for line in lines:
        if not line.strip():
            continue
        event = parse_line(line)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped


def parse_file(path) -> Tuple[List[Event], int]:
    with Path(path).open(encoding="utf-8", errors="ignore") as fh:
        return parse_lines(fh)
