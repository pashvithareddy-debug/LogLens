"""Diagnostic hints: rule-based observations, NOT confirmed root causes."""

from collections import Counter

from .stats import latency_stats

SERVER_MSG = (
    "Elevated server-error rate (5xx).",
    "Check application logs and stack traces, and any recent deploys or config changes.",
)
COMBINED_MSG = (
    "High server-error rate combined with elevated latency.",
    "Check the service behind this endpoint and its downstream dependencies "
    "(databases, third-party APIs) for timeouts or saturation.",
)
CLIENT_MSG = (
    "Elevated client-error rate (4xx).",
    "Check request validation, recent client releases, and broken links or routes.",
)
AUTH_MSG = (
    "Many authentication/authorization failures (401/403).",
    "Check credential/token expiry and auth configuration; see suspicious activity "
    "if client IPs are available.",
)
LIMIT_MSG = (
    "Rate limiting (429) is being triggered.",
    "Check whether limits are sized correctly or a client is over-polling.",
)
LATENCY_MSG = (
    "Latency is elevated.",
    "Look at slow queries, cache misses, heavy payloads or resource contention.",
)


def build_hints(by_endpoint, overall_avg_ms, slow_ms, min_requests=5, limit=5):
    hints = []
    for endpoint, evs in by_endpoint.items():
        n = len(evs)
        if n < min_requests:
            continue
        codes = Counter(e.status for e in evs)
        errs = sum(c for s, c in codes.items() if s >= 400)
        server = sum(c for s, c in codes.items() if s >= 500)
        rate = errs / n
        times = [e.response_ms for e in evs if e.response_ms is not None]
        stats = latency_stats(times)
        elevated = bool(times) and (
            (overall_avg_ms and stats["average_ms"] >= 1.5 * overall_avg_ms)
            or stats["p95_ms"] > slow_ms
        )
        auth, limited = codes[401] + codes[403], codes[429]

        findings, combined = [], False
        if rate >= 0.10 and server * 2 >= errs:
            combined = elevated
            findings.append(COMBINED_MSG if combined else SERVER_MSG)
        if auth >= 3 and auth / n >= 0.2:
            findings.append(AUTH_MSG)
        if limited >= 3 and limited / n >= 0.05:
            findings.append(LIMIT_MSG)
        if rate >= 0.10 and not findings:
            findings.append(CLIENT_MSG)
        if elevated and not combined:
            findings.append(LATENCY_MSG)
        if not findings:
            continue

        evidence = [f"Error rate: {rate * 100:.1f}% ({errs} of {n} requests)"]
        if times:
            evidence.append(
                f"Average latency: {stats['average_ms']:.0f} ms, P95: {stats['p95_ms']:.0f} ms"
            )
        top_errors = [
            f"{s} x{c}" for s, c in sorted(codes.items(), key=lambda kv: -kv[1]) if s >= 400
        ][:3]
        if top_errors:
            evidence.append("Most common errors: " + ", ".join(top_errors))
        hints.append(
            (
                rate,
                stats["p95_ms"] or 0,
                {
                    "endpoint": endpoint,
                    "requests": n,
                    "error_rate": round(rate, 4),
                    "evidence": evidence,
                    "findings": [{"possible_issue": a, "investigate": b} for a, b in findings],
                },
            )
        )
    hints.sort(key=lambda t: (-t[0], -t[1], t[2]["endpoint"]))
    return [h for _, _, h in hints[:limit]]
