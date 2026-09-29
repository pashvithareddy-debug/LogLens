"""Rule-based suspicious-pattern detection. Flags patterns, never confirmed attacks."""

import re
from collections import Counter, defaultdict

AUTH_FAIL_MIN = 10  # 401/403 responses for one client
RATE_PER_MIN = 60  # requests from one client within a single minute
PROBE_DISTINCT_MIN = 3  # distinct commonly-probed paths
NOT_FOUND_DISTINCT_MIN = 10  # distinct paths that returned 404

PROBE_RE = re.compile(
    r"(\.env|\.git|wp-admin|wp-login|phpmyadmin|etc/passwd|\.\./|xmlrpc|cgi-bin|\.php|/admin)",
    re.IGNORECASE,
)


def detect_suspicious(events):
    by_ip = defaultdict(list)
    for e in events:
        if e.ip:
            by_ip[e.ip].append(e)

    found = []
    for ip, evs in by_ip.items():
        auth_failures = sum(1 for e in evs if e.status in (401, 403))
        per_minute = Counter(e.timestamp.strftime("%Y-%m-%d %H:%M") for e in evs if e.timestamp)
        peak = max(per_minute.values(), default=0)
        probes = {e.endpoint for e in evs if PROBE_RE.search(e.endpoint)}
        missing = {e.endpoint for e in evs if e.status == 404}

        patterns = []
        if auth_failures >= AUTH_FAIL_MIN:
            patterns.append(f"Repeated 401/403 responses ({auth_failures})")
        if peak >= RATE_PER_MIN:
            patterns.append(f"High request rate (peak {peak}/min)")
        if len(probes) >= PROBE_DISTINCT_MIN:
            patterns.append(f"Requests to commonly probed paths ({len(probes)} distinct)")
        if len(missing) >= NOT_FOUND_DISTINCT_MIN:
            patterns.append(f"Many distinct 404 paths ({len(missing)})")
        if patterns:
            found.append(
                {
                    "client": ip,
                    "requests": len(evs),
                    "auth_failures": auth_failures,
                    "peak_requests_per_min": peak,
                    "patterns": patterns,
                }
            )
    found.sort(key=lambda f: (-len(f["patterns"]), -f["requests"], f["client"]))
    return found
