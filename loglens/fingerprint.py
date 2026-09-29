"""Error fingerprinting: group failures that are 'the same bug' together."""

import re
from collections import defaultdict

_ID_RE = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,})$"
)


def normalize_endpoint(path: str) -> str:
    """/api/orders/1041 -> /api/orders/:id (numeric, UUID and long-hex segments)."""
    return "/".join(":id" if _ID_RE.match(part) else part for part in path.split("/"))


def group_errors(errors, top=5):
    groups = defaultdict(list)
    for e in errors:
        groups[(e.method, normalize_endpoint(e.endpoint), e.status)].append(e)
    rows = []
    for (method, endpoint, status), evs in groups.items():
        stamps = [e.timestamp for e in evs if e.timestamp]
        rows.append(
            {
                "method": method,
                "endpoint": endpoint,
                "status": status,
                "count": len(evs),
                "first_seen": min(stamps).isoformat() if stamps else None,
                "last_seen": max(stamps).isoformat() if stamps else None,
            }
        )
    rows.sort(key=lambda r: (-r["count"], r["endpoint"], r["status"]))
    return rows[:top]
