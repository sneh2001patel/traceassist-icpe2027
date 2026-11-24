"""Late-cycle window finder for periodic threads.

Derives a per-activation period signal for one thread -- the time between
consecutive wake-ups (BLOCKED -> RUNNING transitions) in the Control Flow
intervals -- and runs TMLL's own `ZScoreStrategy` on it. Each flagged cycle is
returned as a window; explaining it (CPU occupancy, critical path, the
thread's own work) is done by the Java unified explainer from Trace
Compass's exact state system (unified_architecture_design.pdf).

TMLL's packaged `AnomalyDetection` module needs a `TMLLClient`/`Experiment`
to fetch its own data, but its strategy classes work on any pandas
DataFrame, which is how they are used here: no TMLL fork needed.
"""

from __future__ import annotations

import argparse
import json
import statistics
from typing import Any

import pandas as pd

from tmll_control_flow_probe_syscall_v1 import fetch_control_flow


# Mirrors tmll.ml.modules.anomaly_detection.anomaly_detection_module's own
# MINIMUM_REQUIRED_DATAPOINTS constant.
MINIMUM_REQUIRED_DATAPOINTS = 10


# ---------------------------------------------------------------------------
# Stage A -- detect
# ---------------------------------------------------------------------------


def _gap_state_breakdown(
    intervals: list[dict[str, Any]], start_ns: int, end_ns: int
) -> dict[str, int]:
    """Nanoseconds the thread itself spent in each state within [start, end)."""
    breakdown: dict[str, int] = {}
    for interval in intervals:
        overlap = min(int(interval["end_timestamp_exclusive_ns"]), end_ns) - max(
            int(interval["start_timestamp_ns"]), start_ns
        )
        if overlap <= 0:
            continue
        state = str(interval.get("state", "UNKNOWN"))
        breakdown[state] = breakdown.get(state, 0) + overlap
    return breakdown


def _running_ns(breakdown_ns: dict[str, int]) -> int:
    return sum(ns for state, ns in breakdown_ns.items() if state.startswith("RUNNING"))


def _classify_gap(breakdown_ns: dict[str, int]) -> dict[str, Any]:
    """What the thread itself was mostly doing during a late cycle's gap:
    blocked, waiting for a CPU, running, or mixed. A hint for readers of the
    window; the Java explainer recomputes the exact split."""
    total = sum(breakdown_ns.values())
    blocked = breakdown_ns.get("BLOCKED", 0)
    waiting = breakdown_ns.get("RUNNABLE_WAITING_FOR_CPU", 0)
    running = _running_ns(breakdown_ns)
    if total and blocked * 2 >= total:
        kind = "blocked"
    elif total and waiting * 2 >= total:
        kind = "waiting_for_cpu"
    elif total and running * 2 >= total:
        kind = "running"
    else:
        kind = "mixed"
    return {
        "gap_kind": kind,
        "gap_state_percent": {
            state: ns * 100.0 / total for state, ns in sorted(breakdown_ns.items())
        }
        if total
        else {},
    }


def _zscore_flags(df: pd.DataFrame, column: str, zscore_threshold: float) -> tuple[pd.Series, bool]:
    """Per-point anomaly flags for ``df[column]`` from TMLL's ZScoreStrategy,
    with the fallback described below. Returns (flags, fallback_used).
    Shared by the period-jitter detector and the series endpoint."""
    # Imported lazily so this module can be unit-tested without a TMLL
    # install being on the path unless this specific function is called.
    from tmll.ml.modules.anomaly_detection.strategies.zscore import (
        ZScoreStrategy,
    )

    strategy = ZScoreStrategy()
    anomalies_df, _grouped_periods = strategy.detect_anomalies(
        df, zscore_threshold=zscore_threshold
    )
    # Deliberately NOT using _grouped_periods here: AnomalyDetectionStrategy
    # ._identify_anomaly_periods() only reports a "period" when >=90% of an
    # adaptive window (>=10 points) is anomalous -- designed for sustained
    # bursts, not a single isolated spike in an otherwise-clean series, which
    # is exactly what a one-off scheduling delay looks like. Reading the
    # per-point "*_is_anomaly" column directly catches isolated spikes that
    # the windowed grouping would silently drop.
    flag_column = f"{column}_is_anomaly"
    flagged = (
        anomalies_df[flag_column]
        if flag_column in anomalies_df
        else pd.Series(False, index=df.index)
    )
    fallback_used = False

    # TMLL's ZScoreStrategy (and IQRStrategy) both call
    # AnomalyDetectionStrategy._remove_minimum() before scoring, which drops
    # *every* row tied at the column's minimum -- not just one row. That is
    # a reasonable choice for a signal like CPU%/Disk I/O, where a shared
    # minimum usually means "idle floor, not interesting." It is the wrong
    # choice here: a healthy periodic thread's period signal is almost all
    # ties at the same minimum (the nominal period itself), so on a very
    # clean signal (little or no natural jitter) this preprocessing can
    # strip out nearly the entire baseline, leaving too few points for
    # scipy.stats.zscore to run at all -- which surfaces not as an error,
    # but as a silent "no anomalies found," even with an obvious 10x spike
    # present (confirmed directly: see the module's own test run in
    # periodic_thread_delay_design.md's implementation notes). Detect that
    # degenerate case and fall back to the same z-score math applied
    # directly to the untouched series, rather than trust a negative result
    # that TMLL's own preprocessing choice, not the data, produced.
    if not flagged.any() and len(df) >= MINIMUM_REQUIRED_DATAPOINTS:
        tied_at_minimum = int((df[column] == df[column].min()).sum())
        if tied_at_minimum / len(df) > 0.5:
            import warnings

            from scipy import stats as _stats

            with warnings.catch_warnings():
                # A genuinely zero-variance series (no delay at all, and no
                # measurable jitter either) makes zscore's internal moment
                # calculation degenerate -- scipy warns, and correctly
                # produces NaN/0 scores that never exceed the threshold.
                # That is the right answer (no anomaly), just a noisy way
                # to get there; the warning is expected, not a sign
                # something is wrong.
                warnings.filterwarnings(
                    "ignore",
                    message="Precision loss occurred in moment calculation",
                )
                z_scores = _stats.zscore(df[column])
            flagged = pd.Series(
                (z_scores > zscore_threshold) & (~pd.isna(z_scores)),
                index=df.index,
            )
            fallback_used = True

    return flagged, fallback_used


def detect_periodic_jitter_anomalies(
    detailed: dict[str, Any],
    expected_period_ns: int | None = None,
    zscore_threshold: float = 3.0,
) -> dict[str, Any]:
    """Stage A. ``detailed`` is the dict `fetch_control_flow()` already
    returns for one TID (same object `analyze_thread()` uses) -- this
    function does not perform any new Trace Server fetch of its own.

    Returns one entry per anomalous activation, each carrying the gap
    window (``gap_start_timestamp_ns``/``gap_end_timestamp_ns``) Stage B
    needs to correlate against the Resources Status view.
    """
    intervals = sorted(
        detailed.get("intervals", []),
        key=lambda interval: interval["start_timestamp_ns"],
    )
    # An "activation" of a periodic thread means it just woke from sleep
    # (BLOCKED -> ... -> RUNNING), not merely that it resumed after any
    # RUNNING interval, however that interval ended. On a real, noisy
    # system a single logical ~1ms cycle of work routinely gets chopped
    # into several separate RUNNING bursts by brief involuntary
    # preemptions that have nothing to do with the thread's own period.
    # Treating every fragment as its own "activation" wildly overcounts
    # (confirmed directly: periodic_delay_demo.c's periodic_thread, which
    # really does exactly 800 usleep()-driven cycles, showed 1721 raw
    # RUNNING intervals at fine resolution).
    #
    # The real state sequence for a genuine wake (also confirmed directly
    # against that trace) is BLOCKED -> RUNNABLE_WAITING_FOR_CPU ->
    # RUNNING, not BLOCKED -> RUNNING directly -- Trace Compass's
    # canonical name for "preempted"/"ready but not on a CPU yet" is
    # RUNNABLE_WAITING_FOR_CPU, and every genuine wake passes through it
    # for at least a few microseconds before the scheduler actually grants
    # the CPU. So: walk backward from each RUNNING interval, skipping over
    # any immediately preceding RUNNABLE_WAITING_FOR_CPU interval(s), and
    # only count this as a new activation if what comes before *that* is
    # BLOCKED. A RUNNING interval preceded directly by another RUNNING
    # interval (or by RUNNABLE_WAITING_FOR_CPU that itself follows RUNNING)
    # is a same-cycle fragment, not a new activation.
    running_starts = []
    previous_non_waiting_state = None
    for interval in intervals:
        state = str(interval.get("state", ""))
        if state == "RUNNABLE_WAITING_FOR_CPU":
            continue
        if state.startswith("RUNNING") and previous_non_waiting_state == "BLOCKED":
            running_starts.append(interval["start_timestamp_ns"])
        previous_non_waiting_state = state
    running_starts = sorted(running_starts)

    if len(running_starts) < 3:
        return {
            "available": False,
            "reason": (
                f"Only {len(running_starts)} observed activation(s) for "
                "this thread; at least 3 are needed to establish a period "
                "baseline."
            ),
        }

    period_ns = [
        later - earlier
        for earlier, later in zip(running_starts[:-1], running_starts[1:])
    ]
    # The activation timestamp that ENDS each period (i.e. period_ns[i] is
    # the gap between running_starts[i] and running_starts[i + 1]).
    activation_ts_ns = running_starts[1:]

    if expected_period_ns is None:
        expected_period_ns = int(statistics.median(period_ns))

    df = pd.DataFrame(
        {"period_ms": [p / 1_000_000.0 for p in period_ns]},
        index=pd.to_datetime(activation_ts_ns, unit="ns"),
    )

    flagged, fallback_used = _zscore_flags(df, "period_ms", zscore_threshold)

    # Each cycle against the cycles around it (the 50 before and 50 after): a
    # cycle that is late against the whole run's median may be normal for its
    # part of the run (a program that slowed down), and a z-score on a very
    # regular loop flags overruns of a few percent.
    def local_period_ns(position: int) -> int:
        lo = max(0, position - 50)
        hi = min(len(period_ns), position + 51)
        around = period_ns[lo:position] + period_ns[position + 1:hi]
        return int(statistics.median(around)) if around else expected_period_ns

    def local_size(factor: float) -> str:
        if factor >= 5:
            return "major: at least 5 times the cycles around it"
        if factor >= 2:
            return "noticeable: 2 to 5 times the cycles around it"
        return "small: under twice the cycles around it"

    anomalies: list[dict[str, Any]] = []
    for position, is_anomaly in enumerate(flagged.tolist()):
        if not bool(is_anomaly):
            continue
        observed_period_ns = period_ns[position]
        local_ns = local_period_ns(position)
        local_factor = observed_period_ns / local_ns if local_ns else 0.0
        activation_ns = activation_ts_ns[position]
        gap_start_ns = running_starts[position]
        breakdown_ns = _gap_state_breakdown(intervals, gap_start_ns, activation_ns)
        anomalies.append(
            {
                **_classify_gap(breakdown_ns),
                "activation_timestamp_ns": activation_ns,
                "gap_start_timestamp_ns": gap_start_ns,
                "gap_end_timestamp_ns": activation_ns,
                "expected_activation_timestamp_ns": gap_start_ns
                + expected_period_ns,
                "observed_period_ns": observed_period_ns,
                "observed_period_ms": observed_period_ns / 1_000_000.0,
                "expected_period_ns": expected_period_ns,
                "expected_period_ms": expected_period_ns / 1_000_000.0,
                "delay_ns": observed_period_ns - expected_period_ns,
                "delay_ms": (observed_period_ns - expected_period_ns)
                / 1_000_000.0,
                "delay_factor": (
                    observed_period_ns / expected_period_ns
                    if expected_period_ns
                    else None
                ),
                "local_period_ms": local_ns / 1_000_000.0,
                "local_delay_ms": (observed_period_ns - local_ns) / 1_000_000.0,
                "local_delay_factor": local_factor,
                "local_size": local_size(local_factor),
            }
        )

    anomalies.sort(key=lambda item: item["delay_ns"], reverse=True)

    # The longest cycle, flagged or not: "no late cycle" is only checkable against a threshold
    # (e.g. 5 times the normal period) if the worst case is reported too.
    longest_index = max(range(len(period_ns)), key=lambda i: period_ns[i])
    ordered = sorted(period_ns)
    p99_ns = ordered[min(len(ordered) - 1, int(0.99 * len(ordered)))]

    longest_local_ns = local_period_ns(longest_index)
    longest_local_factor = period_ns[longest_index] / longest_local_ns if longest_local_ns else 0.0
    size_counts = {"major": 0, "noticeable": 0, "small": 0}
    for anomaly in anomalies:
        size_counts[anomaly["local_size"].split(":")[0]] += 1

    return {
        "available": True,
        "tid": detailed.get("tid"),
        "longest_local_period_ms": longest_local_ns / 1_000_000.0,
        "longest_local_factor": longest_local_factor,
        "longest_local_size": local_size(longest_local_factor),
        "late_cycles_by_size": size_counts,
        "activation_count": len(running_starts),
        "longest_period_ms": period_ns[longest_index] / 1_000_000.0,
        "longest_period_factor": (period_ns[longest_index] / expected_period_ns if expected_period_ns else None),
        "longest_period_end_timestamp_ns": activation_ts_ns[longest_index],
        "p99_period_ms": p99_ns / 1_000_000.0,
        "first_activation_timestamp_ns": running_starts[0],
        "last_activation_timestamp_ns": running_starts[-1],
        "expected_period_ns": expected_period_ns,
        "expected_period_ms": expected_period_ns / 1_000_000.0,
        "zscore_threshold": zscore_threshold,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "method": (
            "zscore, computed directly on the untouched period series "
            "(TMLL's own ZScoreStrategy preprocessing degenerates on this "
            "signal shape -- see fallback_reason)"
            if fallback_used
            else (
                "zscore (TMLL's own ZScoreStrategy, run directly against a "
                "locally-derived inter-activation period signal)"
            )
        ),
        "fallback_used": fallback_used,
        "fallback_reason": (
            "More than half of all observed periods are tied at the exact "
            "same minimum value (a very clean, low-jitter periodic "
            "signal). TMLL's ZScoreStrategy/IQRStrategy both drop every "
            "row tied at the minimum before scoring, which on this signal "
            "shape strips out nearly the whole baseline and silently "
            "yields zero anomalies regardless of how extreme a real delay "
            "is. Recomputed the same z-score threshold directly on the "
            "untouched series instead."
            if fallback_used
            else None
        ),
        "note": (
            "The period signal is derived from the same RUNNING-state "
            "intervals fetch_control_flow() already retrieves for this "
            "TID -- no new Trace Server output was needed for detection. "
            "See periodic_thread_delay_design.md, Stage A."
        ),
    }


# ---------------------------------------------------------------------------
# Stage B -- explain
# ---------------------------------------------------------------------------



def detect_series_anomalies(
    values_ms: list[float],
    timestamps_ns: list[int] | None = None,
    zscore_threshold: float = 3.0,
) -> dict[str, Any]:
    """TMLL's z-score over a series of durations measured elsewhere (one
    value per occurrence, e.g. each wait of a process's main thread on its
    bottleneck thread), to tell a constant slowdown (every occurrence alike)
    from occasional spikes."""
    values = [float(v) for v in values_ms]
    if len(values) < 3:
        return {"available": False, "reason": f"only {len(values)} value(s); at least 3 are needed"}
    if timestamps_ns is None or len(timestamps_ns) != len(values):
        timestamps_ns = list(range(len(values)))
    df = pd.DataFrame({"value_ms": values}, index=pd.to_datetime(list(timestamps_ns), unit="ns"))
    flagged, fallback_used = _zscore_flags(df, "value_ms", zscore_threshold)
    ordered = sorted(values)

    def percentile(q: float) -> float:
        return ordered[min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))]

    anomalies = []
    for position, is_anomaly in enumerate(flagged.tolist()):
        if bool(is_anomaly):
            anomalies.append({
                "index": position,
                "value_ms": round(values[position], 3),
                "timestamp_ns": int(timestamps_ns[position]),
            })
    median = statistics.median(values)
    return {
        "available": True,
        "count": len(values),
        "mean_ms": round(statistics.fmean(values), 3),
        "median_ms": round(median, 3),
        "p99_ms": round(percentile(0.99), 3),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
        "stdev_ms": round(statistics.pstdev(values), 3),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies[:50],
        "zscore_threshold": zscore_threshold,
        "method": "TMLL ZScoreStrategy" + (" (direct z-score fallback)" if fallback_used else ""),
    }


def analyze_periodic_jitter(
    host: str,
    port: int,
    tid: int,
    experiment_id: str,
    experiment_name: str,
    expected_period_ns: int | None,
    zscore_threshold: float,
    resolution: str,
) -> dict[str, Any]:
    """Find the thread's late cycles (the window finder)."""
    detailed = fetch_control_flow(
        host=host,
        port=port,
        tid=tid,
        experiment_id=experiment_id,
        trace_paths=None,
        experiment_name=experiment_name,
        start=None,
        end=None,
        resolution=resolution,
    )
    return {
        "stage_a": detect_periodic_jitter_anomalies(
            detailed,
            expected_period_ns=expected_period_ns,
            zscore_threshold=zscore_threshold,
        )
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find a periodic thread's late cycles (TMLL z-score over the "
            "time between its wake-ups)."
        )
    )
    parser.add_argument("--experiment", required=True, help="Trace Server experiment UUID")
    parser.add_argument("--tid", type=int, required=True)
    parser.add_argument("--expected-period-ns", type=int, default=None)
    parser.add_argument("--zscore-threshold", type=float, default=3.0)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--name", default="periodic-jitter-probe")
    parser.add_argument("--resolution", default="100us")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = analyze_periodic_jitter(
        host=args.host,
        port=args.port,
        tid=args.tid,
        experiment_id=args.experiment,
        experiment_name=args.name,
        expected_period_ns=args.expected_period_ns,
        zscore_threshold=args.zscore_threshold,
        resolution=args.resolution,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
