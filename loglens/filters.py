import re
from typing import Iterable, List, Optional

from .models import Event

_STATUS_RE = re.compile(r"^(\d{3}|[1-5]xx)$", re.IGNORECASE)


def _status_matcher(value: str):
    value = value.strip()
    if not _STATUS_RE.match(value):
        raise ValueError(f"invalid status filter {value!r} (use e.g. 500 or 5xx)")
    if value[1:].lower() == "xx":
        hundred = int(value[0])
        return lambda s: s // 100 == hundred
    code = int(value)
    return lambda s: s == code


def _endpoint_matches(endpoint: str, wanted: str) -> bool:
    wanted = wanted.rstrip("/") or "/"
    return endpoint == wanted or endpoint.startswith(wanted.rstrip("/") + "/")


def filter_events(
    events: Iterable[Event],
    status: Optional[str] = None,
    endpoint: Optional[str] = None,
    level: Optional[str] = None,
    method: Optional[str] = None,
) -> List[Event]:
    match_status = _status_matcher(status) if status else None
    level = level.upper() if level else None
    method = method.upper() if method else None
    out = []
    for e in events:
        if match_status and not match_status(e.status):
            continue
        if endpoint and not _endpoint_matches(e.endpoint, endpoint):
            continue
        if level and e.level != level:
            continue
        if method and e.method != method:
            continue
        out.append(e)
    return out
