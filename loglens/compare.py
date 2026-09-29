"""Compare two analysis results (e.g. yesterday vs today) for regression monitoring."""

# (key, label, getter, kind, higher_is_worse, min_abs_change)
METRICS = [
    ("requests", "Requests", lambda r: r["summary"]["total_requests"], "int", False, 0),
    ("errors", "Errors", lambda r: r["summary"]["errors"], "int", True, 0),
    ("error_rate", "Error rate", lambda r: r["summary"]["error_rate"], "pct", True, 0.005),
    (
        "server_error_rate",
        "5xx rate",
        lambda r: r["summary"]["server_error_rate"],
        "pct",
        True,
        0.005,
    ),
    ("average_ms", "Avg latency", lambda r: r["performance"]["average_ms"], "ms", True, 10),
    ("p95_ms", "P95 latency", lambda r: r["performance"]["p95_ms"], "ms", True, 10),
    ("health_score", "Health score", lambda r: r["health"]["score"], "score", False, 0),
]
REL_THRESHOLD = 0.20


def _change(before, after):
    if before is None or after is None or before == 0:
        return None
    return round((after - before) / before * 100, 1)


def compare_results(a: dict, b: dict, min_requests=5) -> dict:
    metrics, notes = [], []
    for key, label, get, kind, worse_up, floor in METRICS:
        before, after = get(a), get(b)
        change = _change(before, after)
        metrics.append(
            {
                "metric": key,
                "label": label,
                "kind": kind,
                "before": before,
                "after": after,
                "change_pct": change,
            }
        )
        if not worse_up or before is None or after is None or abs(after - before) < floor:
            continue
        if before == 0 and after > 0 and floor:
            notes.append(
                {"level": "warning", "message": f"{label} rose from 0 to {_fmt(after, kind)}"}
            )
        elif change is not None and change >= REL_THRESHOLD * 100:
            notes.append({"level": "warning", "message": f"{label} increased by {change:.1f}%"})
        elif change is not None and change <= -REL_THRESHOLD * 100:
            notes.append(
                {"level": "improvement", "message": f"{label} decreased by {abs(change):.1f}%"}
            )

    before_ep = {r["endpoint"]: r for r in a["endpoint_health"]}
    regressions = []
    for row in b["endpoint_health"]:
        old = before_ep.get(row["endpoint"])
        if not old or old["requests"] < min_requests or row["requests"] < min_requests:
            continue
        issues = []
        if row["error_rate"] - old["error_rate"] >= 0.05:
            issues.append(
                f"error rate {old['error_rate'] * 100:.1f}% -> {row['error_rate'] * 100:.1f}%"
            )
        if (
            old["p95_ms"]
            and row["p95_ms"]
            and row["p95_ms"] - old["p95_ms"] >= 50
            and row["p95_ms"] >= 1.25 * old["p95_ms"]
        ):
            issues.append(f"P95 {old['p95_ms']:.0f} ms -> {row['p95_ms']:.0f} ms")
        if issues:
            regressions.append({"endpoint": row["endpoint"], "issues": issues})
    return {"metrics": metrics, "notes": notes, "endpoint_regressions": regressions}


def _fmt(v, kind):
    if v is None:
        return "-"
    if kind == "pct":
        return f"{v * 100:.1f}%"
    if kind == "ms":
        return f"{v:,.0f} ms"
    if kind == "score":
        return f"{v}/100"
    return f"{v:,}"


def render_comparison(c: dict, label_a: str, label_b: str) -> str:
    out = [
        "LOG COMPARISON",
        "─" * 62,
        f"{'Metric':<16}{label_a[:16]:>16}{label_b[:16]:>16}{'Change':>10}",
    ]
    for m in c["metrics"]:
        ch = "-" if m["change_pct"] is None else f"{m['change_pct']:+.1f}%"
        out.append(
            f"{m['label']:<16}{_fmt(m['before'], m['kind']):>16}"
            f"{_fmt(m['after'], m['kind']):>16}{ch:>10}"
        )
    out.append("")
    for n in c["notes"]:
        out.append(("⚠ " if n["level"] == "warning" else "✓ ") + n["message"])
    if not c["notes"]:
        out.append("No significant changes.")
    if c["endpoint_regressions"]:
        out.append("\nEndpoint regressions:")
        for r in c["endpoint_regressions"]:
            out.append(f"  {r['endpoint']}: " + "; ".join(r["issues"]))
    return "\n".join(out)
