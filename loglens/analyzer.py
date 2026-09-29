"""Turns a list of Events into a plain-dict analysis result (JSON-serializable)."""

from collections import Counter, defaultdict
from typing import Iterable

from .fingerprint import group_errors
from .hints import build_hints
from .models import Event
from .security import detect_suspicious
from .stats import latency_stats

# Max points each factor can subtract from the 100-point health score.
PENALTY_CAPS = {"errors": 30, "server_errors": 40, "latency": 20, "anomalies": 10}


def _rate(part, whole):
    return part / whole if whole else 0.0


def _find_anomalies(groups, scope, total, total_errors, min_requests):
    """Flag groups whose error rate is far above the rate of everything else."""
    found = []
    for name, (n, errs) in groups.items():
        rest = total - n
        if n < min_requests or rest <= 0:
            continue
        current = errs / n
        normal = (total_errors - errs) / rest
        if current >= 0.10 and current >= 2 * normal and current - normal >= 0.10:
            found.append(
                {
                    "scope": scope,
                    "name": name,
                    "requests": n,
                    "normal_error_rate": round(normal, 4),
                    "current_error_rate": round(current, 4),
                }
            )
    return sorted(found, key=lambda a: -a["current_error_rate"])


def analyze(events: Iterable[Event], slow_ms=500.0, top=5, min_requests=5) -> dict:
    events = list(events)
    total = len(events)
    errors = [e for e in events if e.status >= 400]
    server_errors = [e for e in events if e.status >= 500]

    by_endpoint = defaultdict(list)
    by_hour = defaultdict(list)
    for e in events:
        by_endpoint[e.endpoint].append(e)
        if e.timestamp:
            by_hour[e.timestamp.strftime("%Y-%m-%d %H:00")].append(e)

    # Endpoint health
    health_rows = []
    for ep, evs in by_endpoint.items():
        errs = sum(1 for e in evs if e.status >= 400)
        stats = latency_stats([e.response_ms for e in evs if e.response_ms is not None])
        health_rows.append(
            {
                "endpoint": ep,
                "requests": len(evs),
                "errors": errs,
                "error_rate": round(_rate(errs, len(evs)), 4),
                "avg_ms": stats["average_ms"],
                "p50_ms": stats["p50_ms"],
                "p95_ms": stats["p95_ms"],
                "p99_ms": stats["p99_ms"],
            }
        )
    health_rows.sort(key=lambda r: (-r["requests"], r["endpoint"]))

    # Performance
    times = [e.response_ms for e in events if e.response_ms is not None]
    overall = latency_stats(times)
    timed = sorted((r for r in health_rows if r["avg_ms"] is not None), key=lambda r: -r["avg_ms"])
    performance = {
        "has_data": bool(times),
        "slow_threshold_ms": slow_ms,
        **overall,
        "slow_requests": sum(1 for t in times if t > slow_ms),
        "timed_requests": len(times),
        "slowest": [{"endpoint": r["endpoint"], "avg_ms": r["avg_ms"]} for r in timed[:top]],
        "fastest": [{"endpoint": r["endpoint"], "avg_ms": r["avg_ms"]} for r in timed[::-1][:top]],
    }

    # Timeline
    req_by_hour = {h: len(v) for h, v in sorted(by_hour.items())}
    err_by_hour = {h: sum(1 for e in v if e.status >= 400) for h, v in sorted(by_hour.items())}
    timeline = {
        "requests_by_hour": req_by_hour,
        "errors_by_hour": err_by_hour,
        "peak_traffic_hour": max(req_by_hour, key=req_by_hour.get) if req_by_hour else None,
        "peak_error_hour": (
            max(err_by_hour, key=err_by_hour.get) if any(err_by_hour.values()) else None
        ),
    }

    # Anomalies (simple statistical thresholds, no ML)
    ep_groups = {
        ep: (len(v), sum(1 for e in v if e.status >= 400)) for ep, v in by_endpoint.items()
    }
    hr_groups = {h: (len(v), sum(1 for e in v if e.status >= 400)) for h, v in by_hour.items()}
    anomalies = _find_anomalies(
        ep_groups, "endpoint", total, len(errors), min_requests
    ) + _find_anomalies(hr_groups, "hour", total, len(errors), min_requests)

    # Clients
    with_ip = [e for e in events if e.ip]
    clients = {
        "has_data": bool(with_ip),
        "top": [
            {"client": k, "requests": v} for k, v in Counter(e.ip for e in with_ip).most_common(top)
        ],
        "top_error_clients": [
            {"client": k, "errors": v}
            for k, v in Counter(e.ip for e in with_ip if e.status >= 400).most_common(top)
        ],
        "suspicious": detect_suspicious(events),
    }

    # Health score
    err_pct = _rate(len(errors), total) * 100
    srv_pct = _rate(len(server_errors), total) * 100
    slow_pct = _rate(performance["slow_requests"], len(times)) * 100
    penalties = {
        "errors": min(PENALTY_CAPS["errors"], err_pct * 0.6),
        "server_errors": min(PENALTY_CAPS["server_errors"], srv_pct * 2),
        "latency": min(PENALTY_CAPS["latency"], slow_pct),
        "anomalies": min(PENALTY_CAPS["anomalies"], 5 * len(anomalies)),
    }
    score = max(0, round(100 - sum(penalties.values())))
    label = "Healthy" if score >= 90 else "Degraded" if score >= 70 else "Critical"

    stamps = [e.timestamp for e in events if e.timestamp]
    return {
        "summary": {
            "total_requests": total,
            "errors": len(errors),
            "error_rate": round(_rate(len(errors), total), 4),
            "client_errors_4xx": len(errors) - len(server_errors),
            "server_errors_5xx": len(server_errors),
            "server_error_rate": round(_rate(len(server_errors), total), 4),
            "first_event": min(stamps).isoformat() if stamps else None,
            "last_event": max(stamps).isoformat() if stamps else None,
        },
        "status_codes": {str(k): v for k, v in sorted(Counter(e.status for e in events).items())},
        "methods": dict(Counter(e.method for e in events).most_common()),
        "levels": dict(Counter(e.level for e in events).most_common()),
        "top_endpoints": [
            {"endpoint": k, "requests": v}
            for k, v in Counter(e.endpoint for e in events).most_common(top)
        ],
        "error_intelligence": {
            "error_groups": group_errors(errors, top),
            "failing_endpoints": [
                {"endpoint": k, "errors": v}
                for k, v in Counter(e.endpoint for e in errors).most_common(top)
            ],
        },
        "endpoint_health": health_rows,
        "performance": performance,
        "timeline": timeline,
        "anomalies": anomalies,
        "hints": build_hints(by_endpoint, overall["average_ms"], slow_ms, min_requests, top),
        "clients": clients,
        "health": {
            "score": score,
            "label": label,
            "penalties": {k: round(v, 1) for k, v in penalties.items()},
            "caps": PENALTY_CAPS,
        },
    }
