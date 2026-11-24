#!/usr/bin/env python3
"""Small HTTP service that exposes TMLL analysis to Trace Compass Java."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time
from pathlib import Path
from typing import Any

import requests

from rag.evidence_builder import EvidenceBuilder
from rag.prompt_builder import PromptBuilder
from rag.retriever import KnowledgeRetriever
from rag.source_fetcher import attach_source_text
from tmll_control_flow_probe_syscall_v1 import (
    PROBE_BUILD_ID,
    fetch_control_flow,
    fetch_futex_contention_rows_for_tid,
    fetch_inet_sock_local_events,
    fetch_syscall_latency_rows_for_tid,
    fetch_table_sample,
    list_experiment_outputs,
)
from periodic_jitter_probe import analyze_periodic_jitter, detect_series_anomalies
from tmll_cache import TraceCache


SERVICE_BUILD_ID = "2026-08-04-rag-context-v1"
_RAG_RETRIEVER: KnowledgeRetriever | None = None


def resolve_experiment_id_by_trace_path(
    host: str, port: int, trace_path: str
) -> tuple[str, str]:
    """Look up the Trace Server experiment UUID that currently wraps
    ``trace_path``.

    Trace Server assigns a fresh experiment UUID every time it restarts or
    an experiment is recreated, so any hand-maintained UUID (a constant, a
    VM argument) silently goes stale the moment that happens -- the Java
    side then keeps analyzing whatever trace that stale UUID used to point
    at instead of the one actually open in the editor, with the TMLL/RAG
    call failing fast and quietly instead of raising a clear error. The
    trace's own filesystem path, on the other hand, is exactly what the
    Java side already has (the trace open in Trace Compass), and it stays
    valid across Trace Server restarts. Resolving the UUID from that path
    on every request removes the class of bug entirely instead of asking
    anyone to keep two separate configs in sync by hand.
    """
    response = requests.get(
        f"http://{host}:{port}/tsp/api/experiments", timeout=10
    )
    response.raise_for_status()

    normalized_target = os.path.normpath(trace_path)
    matches = []
    for experiment in response.json():
        for trace in experiment.get("traces", []):
            if os.path.normpath(trace.get("path", "")) == normalized_target:
                matches.append(experiment)
                break

    if not matches:
        # Not open in the Trace Server (asked from the command line, or from Eclipse, rather than
        # from the VS Code viewer): open it there, as the viewer would, instead of failing.
        return open_experiment(host, port, normalized_target)

    # A trace re-imported after a Trace Server restart can leave an older,
    # now-orphaned experiment registered under the same path. Prefer one
    # that has finished indexing; among those, assume the server lists the
    # most recently created experiment last.
    #
    # Only an experiment whose time range agrees with its own traces is used. The Trace Server
    # keeps an experiment's index by experiment name, so an experiment named after the trace
    # folder ("kernel", shared by many traces) can come back with another trace's index and a
    # range of years; fetching that at 1 us resolution ran this service out of memory. CLOSED
    # experiments (left from before a Trace Server restart) report no range at all.
    usable = [experiment for experiment in matches if experiment_range_is_sane(experiment)]
    if not usable:
        return open_experiment(host, port, normalized_target)
    chosen = usable[-1]

    return chosen["UUID"], chosen["name"]


#: How far an experiment's range may extend beyond its traces' own ranges (clock offsets).
RANGE_SLACK_NS = 1_000_000_000


def experiment_range_is_sane(experiment: dict[str, Any]) -> bool:
    """True when the experiment is indexed and its start and end lie within its traces' range."""
    if experiment.get("indexingStatus") != "COMPLETED":
        return False
    start, end = int(experiment.get("start") or 0), int(experiment.get("end") or 0)
    traces = [t for t in experiment.get("traces", []) if int(t.get("end") or 0) > 0]
    if end <= start or not traces:
        return False
    first = min(int(t["start"]) for t in traces)
    last = max(int(t["end"]) for t in traces)
    return start >= first - RANGE_SLACK_NS and end <= last + RANGE_SLACK_NS


SERVICE_STARTED_AT = time.time()

#: How long to wait for the Trace Server to index a trace it has just opened.
OPEN_TIMEOUT_S = 900


def open_experiment(host: str, port: int, trace_path: str) -> tuple[str, str]:
    """Open ``trace_path`` in the Trace Server as an experiment and wait until it is indexed.

    Both calls are idempotent in the Trace Server (the same path and name give the same trace
    and experiment), so a second request for the same trace finds what the first one opened.
    """
    if not os.path.isdir(trace_path):
        raise ValueError(f"No trace folder at {trace_path!r}")
    parts = Path(trace_path).parts
    name = "traceassist-" + "-".join(parts[-3:]).replace(" ", "_")
    base = f"http://{host}:{port}/tsp/api"
    response = requests.post(f"{base}/traces", json={"parameters": {"uri": trace_path, "name": name}}, timeout=300)
    response.raise_for_status()
    trace_uuid = response.json()["UUID"]
    response = requests.post(
        f"{base}/experiments", json={"parameters": {"name": name, "traces": [trace_uuid]}}, timeout=300
    )
    response.raise_for_status()
    experiment = response.json()
    deadline = time.time() + OPEN_TIMEOUT_S
    while experiment.get("indexingStatus") == "RUNNING":
        if time.time() > deadline:
            raise ValueError(f"The Trace Server is still indexing {trace_path!r} after {OPEN_TIMEOUT_S} s")
        time.sleep(1)
        experiment = requests.get(f"{base}/experiments/{experiment['UUID']}", timeout=30).json()
    if not experiment_range_is_sane(experiment):
        raise ValueError(
            f"The Trace Server's experiment {experiment.get('name')!r} for {trace_path!r} has a time range "
            f"({experiment.get('start')}..{experiment.get('end')}) that does not match its trace; "
            "its index is probably stale (close it in the Trace Server and retry)"
        )
    return experiment["UUID"], experiment["name"]


#: Most samples one Trace Server fetch may be split into (500 s of trace at 1 us). TMLL's client
#: builds the whole list of 65,536-sample chunks up front, so a wrong range of years would fill
#: memory before the first request; this makes it a clear error instead.
MAX_FETCH_SAMPLES = 500_000_000


def _guard_fetch_intervals() -> None:
    try:
        from tmll.tmll_client import TMLLClient
    except ImportError:
        return
    import pandas as pd

    original = TMLLClient._calculate_intervals
    if getattr(original, "_traceassist_guard", False):
        return

    def guarded(self, start: int, end: int, resample_freq: str):
        samples = (int(end) - int(start)) // max(1, pd.to_timedelta(resample_freq).value)
        if samples > MAX_FETCH_SAMPLES:
            raise ValueError(
                f"Refusing to fetch {samples:,} samples ({(int(end) - int(start)) / 1e9:,.0f} s at "
                f"{resample_freq}); the experiment's time range is probably wrong"
            )
        return original(self, start, end, resample_freq)

    guarded._traceassist_guard = True
    TMLLClient._calculate_intervals = guarded


_guard_fetch_intervals()


def duration_by_state(result: dict[str, Any]) -> dict[str, int]:
    """Return Control Flow durations indexed by canonical state name."""
    return {
        str(item["state"]): int(item["duration_ns"])
        for item in result["state_summary"]
    }


def longest_blocked_intervals(
    result: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    """Return the longest sampled BLOCKED intervals with server labels."""
    blocked = [
        interval
        for interval in result.get("intervals", [])
        if interval.get("state") == "BLOCKED"
    ]
    blocked.sort(
        key=lambda interval: (
            -int(interval.get("duration_ns", 0)),
            int(interval.get("start_timestamp_ns", 0)),
        )
    )

    return [
        {
            "rank": rank,
            "start_timestamp_ns": int(interval["start_timestamp_ns"]),
            "end_timestamp_exclusive_ns": int(
                interval["end_timestamp_exclusive_ns"]
            ),
            "duration_ns": int(interval["duration_ns"]),
            "duration_ms": round(
                int(interval["duration_ns"]) / 1_000_000.0,
                3,
            ),
            "trace_server_label": interval.get("trace_server_label"),
            "trace_server_value": interval.get("trace_server_value"),
        }
        for rank, interval in enumerate(blocked[:limit], start=1)
    ]


def compact_thread_analysis(
    result: dict[str, Any],
    max_blocked_intervals: int = 5,
) -> dict[str, Any]:
    """Convert the detailed probe result into context suitable for the LLM."""
    durations = duration_by_state(result)
    running_ns = (
        durations.get("RUNNING_USER_MODE", 0)
        + durations.get("RUNNING_SYSTEM_CALL", 0)
    )
    blocked_ns = durations.get("BLOCKED", 0)
    waiting_cpu_ns = durations.get("RUNNABLE_WAITING_FOR_CPU", 0)
    interrupted_ns = durations.get("INTERRUPTED", 0)

    known_active_ns = sum(
        duration
        for state, duration in durations.items()
        if state not in {"NOT_ALIVE", "UNKNOWN"}
    )

    def milliseconds(nanoseconds: int) -> float:
        return round(nanoseconds / 1_000_000.0, 3)

    def percentage(nanoseconds: int) -> float:
        if known_active_ns == 0:
            return 0.0
        return round(nanoseconds * 100.0 / known_active_ns, 2)

    diagnostic_states = {
        "RUNNING": running_ns,
        "BLOCKED": blocked_ns,
        "RUNNABLE_WAITING_FOR_CPU": waiting_cpu_ns,
        "INTERRUPTED": interrupted_ns,
    }
    dominant_state = max(
        diagnostic_states,
        key=diagnostic_states.get,
        default="UNKNOWN",
    )

    return {
        "tid": result["tid"],
        "experiment_id": result["experiment_id"],
        "experiment_name": result["experiment_name"],
        "resolution": result["requested_resolution"],
        "known_active_duration_ms": milliseconds(known_active_ns),
        "running_ms": milliseconds(running_ns),
        "blocked_ms": milliseconds(blocked_ns),
        "waiting_for_cpu_ms": milliseconds(waiting_cpu_ns),
        "interrupted_ms": milliseconds(interrupted_ns),
        "running_percent_of_known_active": percentage(running_ns),
        "blocked_percent_of_known_active": percentage(blocked_ns),
        "waiting_for_cpu_percent_of_known_active": percentage(waiting_cpu_ns),
        "dominant_state": dominant_state,
        "longest_blocked_intervals": longest_blocked_intervals(
            result,
            max_blocked_intervals,
        ),
        "blocked_interval_note": (
            "Intervals and labels come from the sampled Trace Server Control "
            "Flow/Thread Status provider. A label can name the syscall active "
            "around the blocked state, but it is not yet a latency or wake-up "
            "correlation."
        ),
        "evidence_scope": (
            "Control Flow scheduling states plus the longest sampled blocked "
            "intervals and their Trace Server labels. A separate syscall-latency "
            "and wake-up correlation is still needed before assigning a root cause."
        ),
    }


def correlate_blocked_intervals_with_syscalls(
    blocked_intervals: list[dict[str, Any]],
    syscall_result: dict[str, Any],
) -> dict[str, Any]:
    """Match blocked intervals with same-thread syscall latency segments."""
    correlations = []
    explained_count = 0

    for blocked in blocked_intervals:
        blocked_start = int(blocked["start_timestamp_ns"])
        blocked_end = int(blocked["end_timestamp_exclusive_ns"])
        blocked_duration = max(0, blocked_end - blocked_start)
        overlaps = []

        for syscall in syscall_result.get("rows", []):
            syscall_start = int(syscall["start_timestamp_ns"])
            syscall_end = int(syscall["end_timestamp_exclusive_ns"])
            overlap_start = max(blocked_start, syscall_start)
            overlap_end = min(blocked_end, syscall_end)
            overlap_ns = overlap_end - overlap_start
            if overlap_ns <= 0:
                continue

            overlaps.append(
                {
                    **syscall,
                    "overlap_start_timestamp_ns": overlap_start,
                    "overlap_end_timestamp_exclusive_ns": overlap_end,
                    "overlap_duration_ns": overlap_ns,
                    "overlap_duration_ms": round(
                        overlap_ns / 1_000_000.0,
                        3,
                    ),
                    "blocked_interval_coverage_percent": (
                        0.0
                        if blocked_duration == 0
                        else round(
                            overlap_ns * 100.0 / blocked_duration,
                            2,
                        )
                    ),
                }
            )

        overlaps.sort(
            key=lambda syscall: (
                -int(syscall["overlap_duration_ns"]),
                int(syscall["start_timestamp_ns"]),
            )
        )
        if overlaps:
            explained_count += 1

        correlations.append(
            {
                "blocked_interval": blocked,
                "overlapping_syscall_count": len(overlaps),
                "overlapping_syscalls": overlaps,
            }
        )

    return {
        "available": True,
        "provider_id": syscall_result["provider_id"],
        "scanned_table_rows": syscall_result["scanned_rows"],
        "table_scan_complete": syscall_result["scan_complete"],
        "table_scan_limit": syscall_result["max_rows"],
        "matching_tid_syscall_count": syscall_result[
            "matching_tid_row_count"
        ],
        "blocked_intervals_with_syscall": explained_count,
        "blocked_intervals_without_syscall": (
            len(blocked_intervals) - explained_count
        ),
        "correlations": correlations,
        "interpretation_note": (
            "A same-thread syscall whose [start, end) interval overlaps a "
            "BLOCKED scheduling interval is strong evidence that the thread "
            "blocked while executing that syscall. This identifies the type "
            "of wait, but wake-up correlation is still required to identify "
            "the responsible resource or thread."
        ),
    }


def summarize_syscall_frequency(syscall_result: dict[str, Any]) -> dict[str, Any]:
    """Aggregate syscall-latency rows into per-syscall call counts and rates.

    ``correlate_blocked_intervals_with_syscalls`` explains how long a thread
    was blocked inside a syscall. It says nothing about how *often* a syscall
    was called, so a thread issuing many fast, non-blocking calls (chatty I/O,
    a request-per-connection pattern, an N+1 query loop) never surfaces: each
    call is too short to move a duration percentage, no matter how many of
    them there are.
    """
    rows = syscall_result.get("rows", [])
    if not rows:
        return {
            "available": False,
            "reason": "no syscall-latency rows for this TID",
        }

    counts: dict[str, int] = defaultdict(int)
    total_duration_ns: dict[str, int] = defaultdict(int)
    for row in rows:
        name = str(row.get("system_call") or "unknown")
        counts[name] += 1
        total_duration_ns[name] += int(row.get("duration_ns", 0))

    span_start = min(int(row["start_timestamp_ns"]) for row in rows)
    span_end = max(int(row["end_timestamp_exclusive_ns"]) for row in rows)
    span_seconds = max((span_end - span_start) / 1_000_000_000.0, 1e-9)

    by_syscall = sorted(
        (
            {
                "system_call": name,
                "call_count": count,
                "calls_per_second": round(count / span_seconds, 2),
                "total_duration_ms": round(
                    total_duration_ns[name] / 1_000_000.0, 3
                ),
                "avg_duration_us": round(
                    (total_duration_ns[name] / count) / 1_000.0, 3
                ),
            }
            for name, count in counts.items()
        ),
        key=lambda item: item["calls_per_second"],
        reverse=True,
    )

    return {
        "available": True,
        "span_seconds": round(span_seconds, 3),
        "total_call_count": sum(counts.values()),
        "by_syscall": by_syscall,
        # A scan that hit its row limit saw only part of the trace: counts are lower bounds.
        "table_scan_complete": bool(syscall_result.get("scan_complete", True)),
        "table_rows_scanned": syscall_result.get("scanned_rows"),
        "table_scan_limit": syscall_result.get("max_rows"),
        "interpretation_note": (
            "calls_per_second is call_count divided by this thread's "
            "observed syscall-active span. A high calls_per_second paired "
            "with a low avg_duration_us means the thread issues many fast "
            "calls in quick succession -- overhead invisible to Control Flow "
            "state-duration percentages, since none of those calls is "
            "individually slow enough to move them."
        ),
    }


# Heuristic dispatch table: which extra, more expensive analysis (if any) is
# worth fetching for a thread, based on the syscalls it actually made. Checked
# in this priority order against the *set* of all syscalls the thread made --
# not just the single most-frequent one, since the most-frequent syscall is
# often an unrelated, cheap call (e.g. rt_sigprocmask) while the syscall that
# actually explains a contention problem can rank lower by raw call count and
# still be the more useful thing to investigate further.
#
# "futex_contention", "disk_io", and "cross_host_messaging" each have a
# fetcher implemented below. "critical_path" does not: it uses Trace
# Compass's execution-graph/critical-path analysis (Java-side, not a
# Trace-Server table like the others) for worker-churn patterns
# (clone/wait4/fork). analyze_thread() below only acts on categories that
# have a fetcher; unrecognized/unimplemented categories are reported but
# skipped.
_SYSCALL_CATEGORY_RULES: list[tuple[str, frozenset[str]]] = [
    ("futex_contention", frozenset({"futex"})),
    ("critical_path", frozenset({"clone", "wait4", "fork"})),
    (
        "cross_host_messaging",
        frozenset(
            {
                "sendto",
                "sendmsg",
                "connect",
                "recvfrom",
                "recvmsg",
                "accept",
                "accept4",
            }
        ),
    ),
    ("disk_io", frozenset({"read", "write", "pread64", "pwrite64", "openat", "open"})),
]

_IMPLEMENTED_CATEGORIES = frozenset(
    {"futex_contention", "disk_io", "cross_host_messaging"}
)

_FILE_IO_TRANSFER_SYSCALLS = frozenset({"read", "pread64", "write", "pwrite64"})
_FILE_IO_OPEN_SYSCALLS = frozenset({"open", "openat"})

_CROSS_HOST_OUTBOUND_SYSCALLS = frozenset({"sendto", "sendmsg", "connect"})
_CROSS_HOST_INBOUND_SYSCALLS = frozenset(
    {"recvfrom", "recvmsg", "accept", "accept4"}
)


def classify_dominant_syscalls(syscall_frequency: dict[str, Any]) -> str | None:
    """Pick which extra analysis category (if any) applies to this thread.

    Returns the highest-priority matching category name, or None if the
    thread's syscalls don't match any rule. The caller decides whether that
    category actually has a fetcher wired up yet.
    """
    if not syscall_frequency.get("available"):
        return None

    observed = {
        row.get("system_call")
        for row in syscall_frequency.get("by_syscall", [])
    }

    for category, trigger_names in _SYSCALL_CATEGORY_RULES:
        if observed & trigger_names:
            return category

    return None


def summarize_futex_contention(futex_result: dict[str, Any]) -> dict[str, Any]:
    """Summarize futex-contention rows into wait/wake counts and total wait time.

    Only WAIT rows represent time this thread actually spent blocked on a
    futex (a userspace lock that fell through to the kernel because it was
    contended); WAKE/WAKE_OP rows are the near-instant operations that woke
    some thread and are kept only for context, not counted as blocking time.
    """
    rows = futex_result.get("rows", [])
    if not rows:
        return {
            "available": False,
            "reason": "no futex-contention rows for this TID",
        }

    waits = [row for row in rows if row.get("event_type") == "WAIT"]
    wakes = [
        row for row in rows if row.get("event_type") in ("WAKE", "WAKE_OP")
    ]

    # Sum nanoseconds, not the per-row duration_ms: that is already rounded to
    # 0.001 ms, so sub-microsecond rows would each count as zero.
    total_wait_ms = round(sum(row["duration_ns"] for row in waits) / 1_000_000.0, 3)
    longest_wait = max(
        waits, key=lambda row: row["duration_ms"], default=None
    )
    distinct_locks = sorted(
        {row["futex_uaddr"] for row in rows if row.get("futex_uaddr")}
    )

    return {
        "available": True,
        "wait_count": len(waits),
        "wake_count": len(wakes),
        "total_wait_ms": total_wait_ms,
        "longest_wait_ms": longest_wait["duration_ms"] if longest_wait else 0.0,
        "longest_wait_uaddr": (
            longest_wait["futex_uaddr"] if longest_wait else None
        ),
        "distinct_lock_addresses": len(distinct_locks),
        "thread_name": rows[0].get("thread_name"),
        "table_scan_complete": bool(futex_result.get("scan_complete", True)),
        "table_rows_scanned": futex_result.get("scanned_rows"),
        "interpretation_note": (
            "WAIT rows are time this thread spent blocked on a futex; "
            "WAKE/WAKE_OP rows are near-instant wake operations, not "
            "blocking time. A large total_wait_ms relative to the thread's "
            "known active time indicates lock contention, not CPU or I/O, "
            "is the bottleneck."
        ),
    }


def summarize_disk_io_syscalls(syscall_result: dict[str, Any]) -> dict[str, Any]:
    """Summarize file-I/O syscalls (read/write/open family) for one thread.

    Unlike futex contention, this needs no extra Trace-Server fetch: the
    file-I/O syscalls are already present in the same syscall-latency rows
    used for syscall_frequency/syscall_latency_correlation, so this just
    filters and aggregates rows analyze_thread() already fetched.

    There is deliberately no per-thread byte total from Trace Compass's
    "Disk I/O View" here: that provider's tree has one entry per host trace
    (confirmed by inspecting it directly), not per thread or even per
    device in this experiment, so it has no TID dimension to filter on at
    all. Byte counts below come instead from the syscall table's own
    return_value column, which is only meaningful for read/pread64/write/
    pwrite64 (whose return value is bytes transferred) -- NOT for open/
    openat, whose return value is a file descriptor. Those are counted
    separately and never summed as bytes.

    The table's "file" column is the kernel source file that implements the
    tracepoint (e.g. "fs/read_write.c"), not the path being read or
    written. This function does not report a filename/path, because that
    information is not present in this data; claiming otherwise would be a
    fabricated fact, not a fact this data actually supports.
    """
    rows = syscall_result.get("rows", [])
    transfer_rows = [
        row
        for row in rows
        if row.get("system_call") in _FILE_IO_TRANSFER_SYSCALLS
    ]
    open_rows = [
        row for row in rows if row.get("system_call") in _FILE_IO_OPEN_SYSCALLS
    ]

    if not transfer_rows and not open_rows:
        return {
            "available": False,
            "reason": (
                "no file-I/O syscalls (read/write/open family) for this TID"
            ),
        }

    def bytes_of(row: dict[str, Any]) -> int:
        try:
            value = int(row.get("return_value"))
        except (TypeError, ValueError):
            return 0
        return value if value > 0 else 0

    read_rows = [
        row for row in transfer_rows if row["system_call"] in ("read", "pread64")
    ]
    write_rows = [
        row
        for row in transfer_rows
        if row["system_call"] in ("write", "pwrite64")
    ]

    return {
        "available": True,
        "read_call_count": len(read_rows),
        "write_call_count": len(write_rows),
        "open_call_count": len(open_rows),
        "total_read_bytes": sum(bytes_of(row) for row in read_rows),
        "total_write_bytes": sum(bytes_of(row) for row in write_rows),
        # Summed from nanoseconds: 8,192 page-cache reads of ~0.33us each
        # (slow_request_demo.c) totaled 0.338ms from rounded duration_ms
        # values against 2.718ms actual.
        "total_transfer_duration_ms": round(
            sum(row["duration_ns"] for row in transfer_rows) / 1_000_000.0, 3
        ),
        "interpretation_note": (
            "Byte counts come from read/write syscall return values and "
            "are real transfer sizes. open/openat calls are counted but "
            "contribute no byte total (their return value is a file "
            "descriptor, not a size). These are aggregate counts over every "
            "file the thread touched, including shared libraries loaded at "
            "program start and stdout/stderr. This summary does not know "
            "which file each call used -- do not infer a filename or path "
            "from it; if thread_activity is present, it has the decoded "
            "paths per file."
        ),
    }


def match_cross_host_tcp_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Pair inet_sock_local_out/in events into cross-host message segments.

    Reimplements, in Python, the matching Trace Compass's own
    TcpEventMatching (the "addons" module's event matcher) does: group
    events by (seq, ack_seq, flags) -- the same TCP header identity used
    as the match key -- and pair an "out" (send) event on one host with an
    "in" (receive) event on a DIFFERENT host sharing that key. This exists
    because EventMatchingLatencyAnalysis itself cannot be triggered
    against this combined experiment (its registration does not attach to
    composite multi-trace experiments -- see heuristic_summary.md), not
    because Python duplicates working Java functionality unnecessarily.

    This is a simplified reimplementation, not a byte-for-byte port: it
    does not replicate Trace Compass's internal handling of duplicate or
    retransmitted keys, out-of-order arrival, or unmatched-event
    bookkeeping. For the common case (one out event and one in event per
    key), it produces exactly one segment, same as the real analysis
    would.
    """
    by_key: dict[tuple[int, int, int], list[dict[str, Any]]] = defaultdict(
        list
    )
    for event in events:
        key = (event["seq"], event["ack_seq"], event["flags"])
        by_key[key].append(event)

    segments: list[dict[str, Any]] = []
    for group in by_key.values():
        out_events = [
            event
            for event in group
            if event["event_type"] == "inet_sock_local_out"
        ]
        in_events = [
            event
            for event in group
            if event["event_type"] == "inet_sock_local_in"
        ]

        for out_event in out_events:
            for in_event in in_events:
                if out_event["trace"] == in_event["trace"]:
                    continue

                start_ns = min(
                    out_event["timestamp_ns"], in_event["timestamp_ns"]
                )
                end_ns = max(
                    out_event["timestamp_ns"], in_event["timestamp_ns"]
                )
                segments.append(
                    {
                        "start_timestamp_ns": start_ns,
                        "end_timestamp_exclusive_ns": end_ns,
                        "duration_ns": end_ns - start_ns,
                        "duration_ms": round(
                            (end_ns - start_ns) / 1_000_000.0, 3
                        ),
                        "host_a": out_event["trace"],
                        "host_b": in_event["trace"],
                    }
                )

    return segments


def summarize_cross_host_messaging(
    syscall_rows: dict[str, Any],
    event_matching_result: dict[str, Any],
) -> dict[str, Any]:
    """Attribute cross-host TCP messages to this thread's own syscalls.

    EventMatchingLatencyAnalysis's segments have no TID of their own -- each
    is just [send timestamp, receive timestamp] between two hosts (matches
    on the same host are already discarded by the analysis itself). This
    finds, for each of the thread's own outbound (sendto/sendmsg/connect) or
    inbound (recvfrom/recvmsg/accept/accept4) syscalls, any matched segment
    whose send timestamp falls inside an outbound syscall's interval, or
    whose receive timestamp falls inside an inbound syscall's interval --
    the same timestamp-overlap approach already used in
    correlate_blocked_intervals_with_syscalls(), applied here to segments
    from a different table instead of blocked intervals.

    This is a best-effort correlation, not a guarantee: it can miss a
    message if lttng-modules recorded the inet_sock_local_in/out probe
    slightly outside the syscall's own [start, end) window, and it cannot
    disambiguate two messages on the same connection that both land inside
    one syscall's window.
    """
    if not event_matching_result.get("available", True):
        return {
            "available": False,
            "reason": event_matching_result.get(
                "reason", "Event-matching data was not available."
            ),
        }

    segments = event_matching_result.get("rows", [])
    if not segments:
        return {
            "available": True,
            "message_count": 0,
            "messages": [],
            "interpretation_note": (
                "The cross-host event-matching table was queried but "
                "contained no rows -- either no TCP segments were "
                "successfully matched across hosts in this trace, or the "
                "underlying analysis has not finished being scheduled yet."
            ),
        }

    network_rows = [
        row
        for row in syscall_rows.get("rows", [])
        if row.get("system_call") in _CROSS_HOST_OUTBOUND_SYSCALLS
        or row.get("system_call") in _CROSS_HOST_INBOUND_SYSCALLS
    ]

    messages: list[dict[str, Any]] = []
    for syscall_row in network_rows:
        syscall_name = syscall_row.get("system_call")
        is_outbound = syscall_name in _CROSS_HOST_OUTBOUND_SYSCALLS
        syscall_start = syscall_row.get("start_timestamp_ns")
        syscall_end = syscall_row.get("end_timestamp_exclusive_ns")
        if syscall_start is None or syscall_end is None:
            continue

        for segment in segments:
            anchor_ns = (
                segment["start_timestamp_ns"]
                if is_outbound
                else segment["end_timestamp_exclusive_ns"]
            )
            if not (syscall_start <= anchor_ns <= syscall_end):
                continue

            messages.append(
                {
                    "syscall": syscall_name,
                    "syscall_start_timestamp_ns": syscall_start,
                    "direction": "outbound" if is_outbound else "inbound",
                    "message_send_timestamp_ns": segment[
                        "start_timestamp_ns"
                    ],
                    "message_receive_timestamp_ns": segment[
                        "end_timestamp_exclusive_ns"
                    ],
                    "transit_duration_ms": segment["duration_ms"],
                    "host_a": segment.get("host_a"),
                    "host_b": segment.get("host_b"),
                }
            )

    if not messages:
        return {
            "available": True,
            "message_count": 0,
            "messages": [],
            "scanned_segment_count": len(segments),
            "interpretation_note": (
                "This thread has network syscalls, but none of them "
                "overlapped a matched cross-host TCP segment's send/"
                "receive timestamp. The message may not have been "
                "matched (e.g. UDP, a dropped/retransmitted segment, or "
                "traffic to a host outside this experiment), or it may "
                "be outside the range this analysis has scanned so far."
            ),
        }

    partner_hosts = sorted(
        {
            host
            for message in messages
            for host in (message.get("host_a"), message.get("host_b"))
            if host
        }
    )

    return {
        "available": True,
        "message_count": len(messages),
        "messages": messages,
        "partner_hosts": partner_hosts,
        "total_transit_ms": round(
            sum(message["transit_duration_ms"] for message in messages), 3
        ),
        "scanned_segment_count": len(segments),
        "interpretation_note": (
            "Each entry pairs one of this thread's own network syscalls "
            "with a cross-host TCP segment whose send or receive "
            "timestamp falls inside that syscall's execution window. "
            "host_a/host_b are the two host traces the underlying TCP "
            "packet was matched between -- one of them is this thread's "
            "own host, not necessarily distinguishable from this data "
            "alone. This is a best-effort timestamp correlation, not an "
            "assertion of ground truth."
        ),
    }


def analyze_thread(
    host: str,
    port: int,
    experiment_id: str,
    tid: int,
    resolution: str,
    max_blocked_intervals: int,
    max_syscall_table_rows: int,
    cache: TraceCache | None = None,
    fingerprint: str | None = None,
    cache_report: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fetch and compact thread evidence from the current trace experiment."""
    report = cache_report if cache_report is not None else {}
    detailed = fetch_control_flow(
        host=host,
        port=port,
        tid=tid,
        experiment_id=experiment_id,
        trace_paths=None,
        experiment_name="unused-existing-experiment",
        start=None,
        end=None,
        resolution=resolution,
    )
    analysis = compact_thread_analysis(
        detailed,
        max_blocked_intervals=max_blocked_intervals,
    )

    syscall_rows: dict[str, Any] | None = None
    try:
        syscall_rows = fetch_syscall_latency_rows_for_tid(
            host=host,
            port=port,
            experiment_id=experiment_id,
            tid=tid,
            max_rows=max_syscall_table_rows,
            cache=cache,
            fingerprint=fingerprint,
        )
        report["syscall_table"] = (
            "cached"
            if syscall_rows.get("from_cache")
            else f"scanned {syscall_rows['scanned_rows']:,} rows"
        )
        analysis["syscall_latency_correlation"] = (
            correlate_blocked_intervals_with_syscalls(
                analysis["longest_blocked_intervals"],
                syscall_rows,
            )
        )
        analysis["syscall_frequency"] = summarize_syscall_frequency(syscall_rows)
    except Exception as exc:
        analysis["syscall_latency_correlation"] = {
            "available": False,
            "error": str(exc),
        }
        analysis["syscall_frequency"] = {
            "available": False,
            "error": str(exc),
        }

    # Heuristic gating: only fetch the extra, more expensive analysis this
    # thread's syscalls actually suggest is relevant, instead of always
    # fetching every available Trace-Server analysis for every question.
    dispatch_category = classify_dominant_syscalls(analysis["syscall_frequency"])
    analysis["extra_evidence_dispatch"] = {
        "category": dispatch_category,
        "fetched": dispatch_category in _IMPLEMENTED_CATEGORIES,
    }

    if dispatch_category == "futex_contention":
        try:
            futex_rows = fetch_futex_contention_rows_for_tid(
                host=host,
                port=port,
                experiment_id=experiment_id,
                tid=tid,
                max_rows=max_syscall_table_rows,
                cache=cache,
                fingerprint=fingerprint,
            )
            report["futex_table"] = (
                "cached"
                if futex_rows.get("from_cache")
                else f"scanned {futex_rows['scanned_rows']:,} rows"
            )
            analysis["futex_contention"] = summarize_futex_contention(futex_rows)
        except Exception as exc:
            analysis["futex_contention"] = {
                "available": False,
                "error": str(exc),
            }
    elif dispatch_category == "disk_io":
        try:
            if syscall_rows is None:
                raise RuntimeError(
                    "syscall-latency rows were not available (earlier "
                    "fetch failed), so file-I/O syscalls cannot be "
                    "summarized"
                )
            analysis["disk_io"] = summarize_disk_io_syscalls(syscall_rows)
        except Exception as exc:
            analysis["disk_io"] = {
                "available": False,
                "error": str(exc),
            }
    elif dispatch_category == "cross_host_messaging":
        try:
            if syscall_rows is None:
                raise RuntimeError(
                    "syscall-latency rows were not available (earlier "
                    "fetch failed), so network syscalls cannot be "
                    "correlated"
                )
            network_syscall_rows = [
                row
                for row in syscall_rows.get("rows", [])
                if row.get("system_call") in _CROSS_HOST_OUTBOUND_SYSCALLS
                or row.get("system_call") in _CROSS_HOST_INBOUND_SYSCALLS
            ]
            window_start_ns = None
            window_end_ns = None
            if network_syscall_rows:
                window_start_ns = min(
                    row["start_timestamp_ns"] for row in network_syscall_rows
                )
                window_end_ns = max(
                    row["end_timestamp_exclusive_ns"]
                    for row in network_syscall_rows
                )
            inet_sock_events = fetch_inet_sock_local_events(
                host=host,
                port=port,
                experiment_id=experiment_id,
                start_ns=window_start_ns,
                end_ns=window_end_ns,
            )
            segments = match_cross_host_tcp_events(
                inet_sock_events.get("events", [])
            )
            event_matching_result = {
                "available": True,
                "rows": segments,
            }
            analysis["cross_host_messaging"] = summarize_cross_host_messaging(
                syscall_rows,
                event_matching_result,
            )
        except Exception as exc:
            analysis["cross_host_messaging"] = {
                "available": False,
                "error": str(exc),
            }

    return analysis


def get_rag_retriever() -> KnowledgeRetriever:
    """Return a lazily initialized retriever for the service process."""
    global _RAG_RETRIEVER
    if _RAG_RETRIEVER is None:
        _RAG_RETRIEVER = KnowledgeRetriever()
        if _RAG_RETRIEVER.index.collection.count() == 0:
            _RAG_RETRIEVER.index.build()
    return _RAG_RETRIEVER


def retrieve_documents(question: str, concepts: list[str], limit: int = 6) -> list[dict[str, Any]]:
    """Documentation for the concepts in the findings.

    Each concept (e.g. "fsync", "runnable waiting for CPU") contributes its
    single best document first; the question's own results fill the rest.
    Merging everything by distance instead let the broad question query
    crowd out the concept matches (confirmed: "fsync" and "openat" returned
    no file-I/O document). Source text is fetched live for this request only
    and never stored (see rag/source_fetcher.py).
    """
    retriever = get_rag_retriever()
    selected: list[Any] = []
    seen: set[str] = set()

    def take(document: Any) -> None:
        key = str(document.metadata.get("id") or document.text[:80])
        if key not in seen and len(selected) < limit:
            seen.add(key)
            selected.append(document)

    for concept in concepts[:limit]:
        for document in retriever.search(concept, limit=1):
            take(document)
    if question.strip():
        for document in retriever.search(question, limit=limit):
            take(document)

    documents = attach_source_text(selected)
    return [
        {
            "rank": rank,
            "title": document.metadata.get("title"),
            "domain": document.metadata.get("domain"),
            "source_url": document.metadata.get("source_url"),
            "text": document.text,
            "full_source_text": document.full_source_text,
            "distance": document.distance,
        }
        for rank, document in enumerate(documents, start=1)
    ]


def build_thread_rag_response(
    question: str,
    analysis: dict[str, Any],
    retriever: KnowledgeRetriever | None = None,
    domain: str | None = None,
    limit: int = 6,
) -> dict[str, Any]:
    """Build retrieval context and a grounded prompt for a thread analysis."""
    evidence = EvidenceBuilder.from_thread_analysis(analysis)
    retrieval_query = EvidenceBuilder.build_retrieval_query(question, evidence)
    active_retriever = retriever or get_rag_retriever()
    documents = active_retriever.search(
        retrieval_query,
        domain=domain,
        limit=limit,
    )

    # A second, narrow search for the extra_evidence_dispatch category
    # (e.g. critical_path), merged into the main results. Folding this
    # fact into the main query instead would dilute it -- see
    # EvidenceBuilder.build_category_query()'s docstring.
    category_query = EvidenceBuilder.build_category_query(evidence)
    if category_query:
        category_documents = active_retriever.search(
            category_query,
            domain=domain,
            limit=2,
        )
        documents = KnowledgeRetriever.merge_by_distance(
            documents,
            category_documents,
            limit=limit,
        )

    documents = attach_source_text(documents)
    prompt = PromptBuilder.build(question, evidence, documents)

    return {
        "question": question,
        "evidence": asdict(evidence),
        "retrieval_query": retrieval_query,
        "retrieved_documents": [
            {
                "rank": rank,
                "text": document.text,
                "metadata": document.metadata,
                "distance": document.distance,
                "full_source_text_fetched": document.full_source_text is not None,
            }
            for rank, document in enumerate(documents, start=1)
        ],
        "prompt": prompt,
        "llm_answer": None,
        "note": (
            "This endpoint prepares RAG context only. Trace Compass Java owns "
            "the LLM call and final answer generation."
        ),
    }


class AnalysisHandler(BaseHTTPRequestHandler):
    """Serve health checks and thread-analysis requests."""

    server_version = "TMLLAssistant/0.1"

    def send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def trace_fingerprint(self, experiment_id: str) -> str:
        """Cache key for the trace behind an experiment ("" when disabled)."""
        if not self.server.trace_cache.enabled:
            return ""
        return self.server.trace_cache.fingerprint(
            self.server.trace_server_host,
            self.server.trace_server_port,
            experiment_id,
        )

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path == "/cache/stats":
            self.send_json(HTTPStatus.OK, self.server.trace_cache.stats())
            return
        if self.path == "/health":
            self.send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    # Changes when the service restarts: a client can tell that an answer's
                    # TMLL calls straddled a crash.
                    "started_at": SERVICE_STARTED_AT,
                    "service_build_id": SERVICE_BUILD_ID,
                    "probe_build_id": PROBE_BUILD_ID,
                    "syscall_latency_support": True,
                    "rag_support": True,
                    "llm_support": False,
                    "llm_owner": "tracecompass-java",
                },
            )
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path == "/rag/retrieve":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(content_length) or b"{}")
                started = time.perf_counter()
                documents = retrieve_documents(
                    question=str(body.get("question", "")),
                    concepts=[str(c) for c in body.get("concepts", []) if str(c).strip()],
                    limit=int(body.get("limit", 6)),
                )
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "documents": documents,
                        "timing_ms": {"rag_retrieval_ms": round((time.perf_counter() - started) * 1000, 3)},
                    },
                )
            except Exception as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if self.path == "/analyze/series_anomalies":
            # A series of durations measured by the caller (e.g. each wait of a
            # process's main thread on its bottleneck thread); needs no trace.
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(content_length) or b"{}")
                started = time.perf_counter()
                result = detect_series_anomalies(
                    values_ms=[float(v) for v in body.get("values_ms", [])],
                    timestamps_ns=[int(t) for t in body["timestamps_ns"]] if body.get("timestamps_ns") else None,
                    zscore_threshold=float(body.get("zscore_threshold", 3.0)),
                )
                result["timing_ms"] = {"series_anomalies_ms": round((time.perf_counter() - started) * 1000, 3)}
                self.send_json(HTTPStatus.OK, result)
            except Exception as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if self.path == "/cache/clear":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(content_length) or b"{}")
                fingerprint = None
                if body.get("trace_path"):
                    experiment_id, _ = resolve_experiment_id_by_trace_path(
                        host=self.server.trace_server_host,
                        port=self.server.trace_server_port,
                        trace_path=str(body["trace_path"]).strip(),
                    )
                    fingerprint = self.trace_fingerprint(experiment_id)
                self.server.trace_cache.clear(fingerprint)
                self.send_json(
                    HTTPStatus.OK,
                    {"cleared": "all" if fingerprint is None else fingerprint},
                )
            except Exception as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        supported_paths = {
            "/analyze/thread",
            "/answer/thread",
            "/analyze/periodic_jitter",
            "/experiment/output/table",
            "/experiment/outputs",
        }
        if self.path not in supported_paths:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(content_length))

            trace_path = request.get("trace_path")
            if trace_path:
                experiment_id, _resolved_experiment_name = (
                    resolve_experiment_id_by_trace_path(
                        host=self.server.trace_server_host,
                        port=self.server.trace_server_port,
                        trace_path=str(trace_path).strip(),
                    )
                )
            else:
                # Back-compat path for manual/CLI testing against a known
                # experiment UUID. The Java client always sends trace_path
                # now -- see resolve_experiment_id_by_trace_path().
                experiment_id = str(request["experiment_id"]).strip()
            if not experiment_id:
                raise ValueError("experiment_id must not be empty")

            if self.path == "/experiment/outputs":
                inventory = list_experiment_outputs(
                    host=self.server.trace_server_host,
                    port=self.server.trace_server_port,
                    experiment_id=experiment_id,
                )
                self.send_json(HTTPStatus.OK, inventory)
                return

            if self.path == "/experiment/output/table":
                output_id = str(request["output_id"]).strip()
                start_index = int(request.get("start_index", 0))
                line_count = int(request.get("line_count", 20))
                search_direction = str(
                    request.get("search_direction", "NEXT")
                ).strip().upper()

                if not output_id:
                    raise ValueError("output_id must not be empty")
                if start_index < 0:
                    raise ValueError("start_index must be non-negative")
                if not 1 <= line_count <= 1000:
                    raise ValueError("line_count must be between 1 and 1000")
                if search_direction not in {"NEXT", "PREVIOUS"}:
                    raise ValueError(
                        "search_direction must be NEXT or PREVIOUS"
                    )

                sample = fetch_table_sample(
                    host=self.server.trace_server_host,
                    port=self.server.trace_server_port,
                    experiment_id=experiment_id,
                    output_id=output_id,
                    start_index=start_index,
                    line_count=line_count,
                    search_direction=search_direction,
                )
                self.send_json(HTTPStatus.OK, sample)
                return

            if self.path == "/analyze/periodic_jitter":
                tid = int(request["tid"])
                expected_period_ns = request.get("expected_period_ns")
                expected_period_ns = (
                    None
                    if expected_period_ns is None
                    else int(expected_period_ns)
                )
                zscore_threshold = float(
                    request.get("zscore_threshold", 3.0)
                )
                resolution = str(
                    request.get("resolution", "100us")
                ).strip()

                if tid < 0:
                    raise ValueError("tid must be non-negative")
                if zscore_threshold <= 0:
                    raise ValueError("zscore_threshold must be positive")

                jitter_start = time.perf_counter()
                cache = self.server.trace_cache
                fingerprint = self.trace_fingerprint(experiment_id)
                result, cached = cache.get_or_compute(
                    fingerprint,
                    "periodic_jitter",
                    {
                        "tid": tid,
                        "expected_period_ns": expected_period_ns,
                        "zscore_threshold": zscore_threshold,
                        "resolution": resolution,
                    },
                    lambda: analyze_periodic_jitter(
                        host=self.server.trace_server_host,
                        port=self.server.trace_server_port,
                        tid=tid,
                        experiment_id=experiment_id,
                        experiment_name="unused-existing-experiment",
                        expected_period_ns=expected_period_ns,
                        zscore_threshold=zscore_threshold,
                        resolution=resolution,
                    ),
                )
                jitter_ms = (time.perf_counter() - jitter_start) * 1000

                self.send_json(
                    HTTPStatus.OK,
                    {
                        "periodic_jitter": result,
                        "timing_ms": {
                            "total_ms": round(jitter_ms, 3),
                            "cache": "hit" if cached else (
                                "miss" if cache.enabled else "disabled"
                            ),
                        },
                    },
                )
                return

            tid = int(request["tid"])
            resolution = str(request.get("resolution", "1us")).strip()
            max_blocked_intervals = int(
                request.get("max_blocked_intervals", 5)
            )
            max_syscall_table_rows = int(
                # 200_000 was too shallow for multi-host experiments (e.g.
                # django-benchmark): a TID on a "later" host trace in table
                # order can sit past that many rows, silently making
                # syscall_frequency/correlation come back empty even though
                # matching rows exist further down. 600_000 covered TID 3740
                # in django-benchmark (confirmed present by ~500_000), but
                # was not enough for noferesti-elk-trace (~24M events, ~10x
                # django-benchmark's size): TID 21015's clone/wait4 rows
                # were not found until ~4_000_000 rows scanned. 5_000_000
                # covers both, at the cost of a slower (~3 minute) scan for
                # TIDs whose rows genuinely sit that deep in a large trace.
                request.get("max_syscall_table_rows", 5_000_000)
            )

            if tid < 0:
                raise ValueError("tid must be non-negative")
            if not 1 <= max_blocked_intervals <= 20:
                raise ValueError(
                    "max_blocked_intervals must be between 1 and 20"
                )
            if not 1_000 <= max_syscall_table_rows <= 5_000_000:
                raise ValueError(
                    "max_syscall_table_rows must be between 1000 and 5000000"
                )

            tmll_analysis_start = time.perf_counter()
            cache = self.server.trace_cache
            fingerprint = self.trace_fingerprint(experiment_id)
            table_report: dict[str, str] = {}
            analysis, analysis_cached = cache.get_or_compute(
                fingerprint,
                "analyze_thread",
                {
                    "tid": tid,
                    "resolution": resolution,
                    "max_blocked_intervals": max_blocked_intervals,
                    "max_syscall_table_rows": max_syscall_table_rows,
                },
                lambda: analyze_thread(
                    host=self.server.trace_server_host,
                    port=self.server.trace_server_port,
                    experiment_id=experiment_id,
                    tid=tid,
                    resolution=resolution,
                    max_blocked_intervals=max_blocked_intervals,
                    max_syscall_table_rows=max_syscall_table_rows,
                    cache=cache,
                    fingerprint=fingerprint,
                    cache_report=table_report,
                ),
            )
            tmll_analysis_ms = (time.perf_counter() - tmll_analysis_start) * 1000
            if not cache.enabled:
                cache_summary = "disabled"
            elif analysis_cached:
                cache_summary = "hit (whole thread analysis reused)"
            else:
                cache_summary = "miss" + (
                    " -- " + ", ".join(f"{k}: {v}" for k, v in table_report.items())
                    if table_report
                    else ""
                )

            if self.path == "/answer/thread":
                question = str(request["question"]).strip()
                rag_limit = int(request.get("rag_limit", 6))
                rag_domain = request.get("rag_domain")
                if not question:
                    raise ValueError("question must not be empty")
                if not 1 <= rag_limit <= 20:
                    raise ValueError("rag_limit must be between 1 and 20")
                if rag_domain is not None:
                    rag_domain = str(rag_domain).strip()
                    if not rag_domain:
                        rag_domain = None

                rag_retrieval_start = time.perf_counter()
                rag = build_thread_rag_response(
                    question=question,
                    analysis=analysis,
                    domain=rag_domain,
                    limit=rag_limit,
                )
                rag_retrieval_ms = (
                    (time.perf_counter() - rag_retrieval_start) * 1000
                )
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "analysis": analysis,
                        "rag": rag,
                        "timing_ms": {
                            "tmll_analysis_ms": round(tmll_analysis_ms, 3),
                            "rag_retrieval_ms": round(rag_retrieval_ms, 3),
                            "total_ms": round(
                                tmll_analysis_ms + rag_retrieval_ms, 3
                            ),
                            "cache": cache_summary,
                        },
                    },
                )
                return

            self.send_json(
                HTTPStatus.OK,
                {
                    "analysis": analysis,
                    "timing_ms": {
                        "tmll_analysis_ms": round(tmll_analysis_ms, 3),
                        "total_ms": round(tmll_analysis_ms, 3),
                        "cache": cache_summary,
                    },
                },
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": f"Invalid request: {exc}"},
            )
        except LookupError as exc:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except Exception as exc:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": str(exc)},
            )

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[HTTP] {self.address_string()} - {format % args}")


class AnalysisServer(ThreadingHTTPServer):
    """HTTP server with Trace Server connection settings."""

    trace_server_host: str
    trace_server_port: int
    trace_cache: TraceCache


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Expose TMLL trace analysis through a local HTTP API."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--trace-server-host", default="localhost")
    parser.add_argument("--trace-server-port", type=int, default=8081)
    parser.add_argument(
        "--cache-dir",
        default=str(Path(__file__).resolve().parent / ".tmll_cache"),
        help="Directory for the persistent analysis cache.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Recompute everything on every request.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = AnalysisServer((args.host, args.port), AnalysisHandler)
    server.trace_server_host = args.trace_server_host
    server.trace_server_port = args.trace_server_port
    server.trace_cache = TraceCache(
        None if args.no_cache else Path(args.cache_dir) / "tmll_cache.sqlite"
    )

    print(
        f"TMLL assistant service: http://{args.host}:{args.port}\n"
        f"Trace Server: http://{args.trace_server_host}:"
        f"{args.trace_server_port}\n"
        f"Cache: {server.trace_cache.path or 'disabled'}\n"
        "Press Ctrl+C to stop."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping TMLL assistant service.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
