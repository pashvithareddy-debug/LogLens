from statistics import mean
from typing import List, Optional


def percentile(sorted_values: List[float], p: float) -> Optional[float]:
    """Linear-interpolated percentile of an already-sorted list."""
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def _r(x):
    return None if x is None else round(x, 1)


def latency_stats(times: List[float]) -> dict:
    s = sorted(times)
    return {
        "average_ms": _r(mean(s)) if s else None,
        "p50_ms": _r(percentile(s, 50)),
        "p95_ms": _r(percentile(s, 95)),
        "p99_ms": _r(percentile(s, 99)),
    }
