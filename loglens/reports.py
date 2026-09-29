"""Terminal, JSON and HTML renderers for an analysis result."""

import html
import json
from pathlib import Path

WIDTH = 60


def _pct(x):
    return f"{x * 100:.1f}%"


def _ts(x):
    return x.replace("T", " ") if x else "-"


def _ms(x):
    return "-" if x is None else f"{x:,.0f}"


def _bar(value, maximum, width=20):
    if maximum <= 0 or value <= 0:
        return ""
    return "█" * max(1, round(value / maximum * width))


def _title(text):
    return f"\n{text}\n{'─' * WIDTH}"


def render_terminal(r: dict, source="", filters=None, skipped=0) -> str:
    s, out = r["summary"], []
    out.append(f"LogLens report: {source}" if source else "LogLens report")
    if filters:
        out.append("Filters: " + ", ".join(f"{k}={v}" for k, v in filters.items()))
    if skipped:
        out.append(f"({skipped} unparseable line(s) skipped)")

    out.append(_title("SUMMARY"))
    out.append(f"Total requests: {s['total_requests']}")
    out.append(
        f"Errors:         {s['errors']} ({_pct(s['error_rate'])})  "
        f"[4xx: {s['client_errors_4xx']}, 5xx: {s['server_errors_5xx']}]"
    )
    if s["first_event"]:
        out.append(f"Time range:     {_ts(s['first_event'])}  ->  {_ts(s['last_event'])}")

    out.append(_title("TRAFFIC"))
    out.append("Status codes:  " + "  ".join(f"{k}:{v}" for k, v in r["status_codes"].items()))
    out.append("Methods:       " + "  ".join(f"{k}:{v}" for k, v in r["methods"].items()))
    out.append("Levels:        " + "  ".join(f"{k}:{v}" for k, v in r["levels"].items()))
    out.append("\nMost-used endpoints:")
    for i, row in enumerate(r["top_endpoints"], 1):
        out.append(f"  {i}. {row['endpoint']:<28}{row['requests']:>6}")

    out.append(_title("ERROR INTELLIGENCE"))
    ei = r["error_intelligence"]
    if ei["error_groups"]:
        for i, g in enumerate(ei["error_groups"], 1):
            out.append(
                f"ERROR GROUP #{i}: {g['method']} {g['endpoint']} -> {g['status']}   x{g['count']}"
            )
            out.append(f"    first seen {_ts(g['first_seen'])}   last seen {_ts(g['last_seen'])}")
        out.append("\nEndpoints with most failures:")
        for row in ei["failing_endpoints"]:
            out.append(f"  {row['endpoint']:<28}{row['errors']:>6}")
    else:
        out.append("No 4xx/5xx errors found.")

    out.append(_title("ENDPOINT HEALTH"))
    out.append(f"{'Endpoint':<28}{'Requests':>9}{'Errors':>8}{'Rate':>8}{'Avg ms':>9}{'P95 ms':>9}")
    for row in r["endpoint_health"]:
        out.append(
            f"{row['endpoint']:<28}{row['requests']:>9}{row['errors']:>8}"
            f"{_pct(row['error_rate']):>8}{_ms(row['avg_ms']):>9}{_ms(row['p95_ms']):>9}"
        )

    out.append(_title("PERFORMANCE"))
    p = r["performance"]
    if p["has_data"]:
        out.append(f"Average  {_ms(p['average_ms']):>7} ms")
        out.append(f"P50      {_ms(p['p50_ms']):>7} ms")
        out.append(f"P95      {_ms(p['p95_ms']):>7} ms")
        out.append(f"P99      {_ms(p['p99_ms']):>7} ms")
        out.append(
            f"Slow requests (> {p['slow_threshold_ms']:.0f} ms): "
            f"{p['slow_requests']} of {p['timed_requests']}"
        )
        out.append("\nSlowest endpoints (by average):")
        for i, row in enumerate(p["slowest"], 1):
            out.append(f"  {i}. {row['endpoint']:<28}{row['avg_ms']:>9,.0f} ms")
    else:
        out.append("No response-time data in this log.")

    out.append(_title("TRAFFIC TIMELINE"))
    t = r["timeline"]
    if t["requests_by_hour"]:
        peak = max(t["requests_by_hour"].values())
        for hour, n in t["requests_by_hour"].items():
            errs = t["errors_by_hour"].get(hour, 0)
            out.append(f"{hour[5:]}  {_bar(n, peak):<20} {n:>5}  ({errs} err)")
        out.append(f"\nPeak traffic: {t['peak_traffic_hour']}")
        if t["peak_error_hour"]:
            out.append(f"Peak errors:  {t['peak_error_hour']}")
    else:
        out.append("No timestamps found.")

    out.append(_title("ANOMALIES"))
    if r["anomalies"]:
        for a in r["anomalies"]:
            out.append(
                f"⚠ {a['scope']} {a['name']}: error rate {_pct(a['current_error_rate'])} "
                f"vs {_pct(a['normal_error_rate'])} elsewhere ({a['requests']} requests)"
            )
    else:
        out.append("None detected.")

    out.append(_title("DIAGNOSTIC HINTS"))
    if r["hints"]:
        for h in r["hints"]:
            out.append(f"💡 {h['endpoint']}  ({h['requests']} requests)")
            for ev in h["evidence"]:
                out.append(f"   • {ev}")
            for f in h["findings"]:
                out.append(f"   Possible issue: {f['possible_issue']}")
                out.append(f"   Investigate:    {f['investigate']}")
            out.append("")
        out.append("Hints come from measurable patterns; they are not confirmed root causes.")
    else:
        out.append("Nothing notable.")

    c = r["clients"]
    if c["has_data"]:
        out.append(_title("TOP CLIENTS"))
        for row in c["top"]:
            out.append(f"  {row['client']:<22}{row['requests']:>6} requests")
        if c["top_error_clients"]:
            out.append("\nTop error clients:")
            for row in c["top_error_clients"]:
                out.append(f"  {row['client']:<22}{row['errors']:>6} errors")
        out.append(_title("SUSPICIOUS ACTIVITY"))
        if c["suspicious"]:
            for sc in c["suspicious"]:
                out.append(
                    f"⚠ {sc['client']}  ({sc['requests']} requests, "
                    f"{sc['auth_failures']} auth failures)"
                )
                for pat in sc["patterns"]:
                    out.append(f"   • {pat}")
            out.append("\nRule-based suspicious patterns, not confirmed attacks.")
        else:
            out.append("None detected.")

    h = r["health"]
    inner = 34
    out.append("")
    out.append("╭" + "─" * inner + "╮")
    out.append("│" + "SYSTEM HEALTH".center(inner) + "│")
    out.append("│" + f"{h['score']} / 100  ({h['label']})".center(inner) + "│")
    out.append("│" + " " * inner + "│")
    for name, pen in h["penalties"].items():
        filled = round(pen / h["caps"][name] * 5)
        row = f" {name:<14}{'█' * filled}{'░' * (5 - filled)}  -{pen:.1f}"
        out.append("│" + row.ljust(inner) + "│")
    out.append("╰" + "─" * inner + "╯")
    return "\n".join(out)


def to_json(r: dict) -> str:
    return json.dumps(r, indent=2)


def to_html(r: dict, source="") -> str:
    e = html.escape
    s, h, p, t, c = r["summary"], r["health"], r["performance"], r["timeline"], r["clients"]

    def table(headers, rows):
        head = "".join(f"<th>{e(str(x))}</th>" for x in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{e(str(x))}</td>" for x in row) + "</tr>" for row in rows
        )
        return f"<div class='scroll'><table><tr>{head}</tr>{body}</table></div>"

    def section(title, body):
        return f"<h2>{e(title)}</h2>{body}"

    groups = [
        [
            f"#{i}",
            g["count"],
            g["status"],
            g["method"],
            g["endpoint"],
            _ts(g["first_seen"]),
            _ts(g["last_seen"]),
        ]
        for i, g in enumerate(r["error_intelligence"]["error_groups"], 1)
    ]
    health_rows = [
        [
            x["endpoint"],
            x["requests"],
            x["errors"],
            _pct(x["error_rate"]),
            _ms(x["avg_ms"]),
            _ms(x["p95_ms"]),
            _ms(x["p99_ms"]),
        ]
        for x in r["endpoint_health"]
    ]
    anomaly_rows = [
        [
            a["scope"],
            a["name"],
            _pct(a["current_error_rate"]),
            _pct(a["normal_error_rate"]),
            a["requests"],
        ]
        for a in r["anomalies"]
    ]
    peak = max(t["requests_by_hour"].values(), default=0)
    timeline = "".join(
        f"<div class='row'><span>{e(hr)}</span>"
        f"<div class='bar' style='width:{(n / peak * 100) if peak else 0:.0f}%'></div>"
        f"<span>{n} ({t['errors_by_hour'].get(hr, 0)} err)</span></div>"
        for hr, n in t["requests_by_hour"].items()
    )
    perf = (
        table(
            ["Average", "P50", "P95", "P99"],
            [
                [
                    f"{_ms(p['average_ms'])} ms",
                    f"{_ms(p['p50_ms'])} ms",
                    f"{_ms(p['p95_ms'])} ms",
                    f"{_ms(p['p99_ms'])} ms",
                ]
            ],
        )
        + f"<p>Slow (&gt; {p['slow_threshold_ms']:.0f} ms): <b>{p['slow_requests']}</b> "
        f"of {p['timed_requests']}</p>"
        if p["has_data"]
        else "<p>No response-time data.</p>"
    )
    hints = (
        "".join(
            f"<div class='card'><b>{e(x['endpoint'])}</b> <span class='muted'>({x['requests']} requests)</span><ul>"
            + "".join(f"<li>{e(ev)}</li>" for ev in x["evidence"])
            + "</ul>"
            + "".join(
                f"<p><b>Possible issue:</b> {e(f['possible_issue'])}<br>"
                f"<b>Investigate:</b> {e(f['investigate'])}</p>"
                for f in x["findings"]
            )
            + "</div>"
            for x in r["hints"]
        )
        or "<p>Nothing notable.</p>"
    )
    hints += (
        "<p class='muted'>Hints are based on measurable patterns, not confirmed root causes.</p>"
    )

    client_html = ""
    if c["has_data"]:
        client_html += section(
            "Top clients",
            table(["Client", "Requests"], [[x["client"], x["requests"]] for x in c["top"]]),
        )
        if c["top_error_clients"]:
            client_html += table(
                ["Client", "Errors"], [[x["client"], x["errors"]] for x in c["top_error_clients"]]
            )
        sus = (
            table(
                ["Client", "Requests", "Patterns"],
                [[x["client"], x["requests"], "; ".join(x["patterns"])] for x in c["suspicious"]],
            )
            if c["suspicious"]
            else "<p>None detected.</p>"
        )
        client_html += section(
            "Suspicious activity",
            sus + "<p class='muted'>Rule-based patterns, not confirmed attacks.</p>",
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogLens report</title>
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#ddd;--accent:#2563eb;--bad:#dc2626}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111;--fg:#eee;--muted:#999;--line:#333;--accent:#60a5fa;--bad:#f87171}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:0 auto;padding:24px}}
h1{{margin-bottom:0}} h2{{border-bottom:1px solid var(--line);padding-bottom:4px;margin-top:32px}}
.muted{{color:var(--muted)}} .score{{font-size:48px;font-weight:700;color:var(--accent)}}
.scroll{{overflow-x:auto}} table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}}
.row{{display:flex;align-items:center;gap:10px;margin:3px 0}} .row span:first-child{{width:120px;flex:none}}
.bar{{background:var(--accent);height:14px;border-radius:3px}}
.card{{border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:10px 0}}
</style></head><body>
<h1>LogLens report</h1><p class="muted">{e(source)}</p>
{section("System health", f"<div class='score'>{h['score']} / 100</div><div>{e(h['label'])}</div>")}
{section("Summary", f"<p>{s['total_requests']} requests · {s['errors']} errors ({_pct(s['error_rate'])}) · 4xx: {s['client_errors_4xx']} · 5xx: {s['server_errors_5xx']}</p>")}
{section("Error groups", table(["Group", "Count", "Status", "Method", "Endpoint", "First seen", "Last seen"], groups) if groups else "<p>None.</p>")}
{section("Endpoint health", table(["Endpoint", "Requests", "Errors", "Rate", "Avg ms", "P95 ms", "P99 ms"], health_rows))}
{section("Latency", perf)}
{section("Traffic timeline", timeline or "<p>No timestamps.</p>")}
{section("Anomalies", table(["Scope", "Name", "Current", "Normal", "Requests"], anomaly_rows) if anomaly_rows else "<p>None detected.</p>")}
{section("Diagnostic hints", hints)}
{client_html}
</body></html>"""


def write_report(r: dict, path, source="") -> None:
    path = Path(path)
    ext = path.suffix.lower()
    if ext == ".json":
        path.write_text(to_json(r), encoding="utf-8")
    elif ext in (".html", ".htm"):
        path.write_text(to_html(r, source), encoding="utf-8")
    else:
        raise ValueError("report path must end in .json or .html")
