#!/usr/bin/env python3
"""Retrieve and summarize a Linux Control Flow thread through TMLL.

This is a first integration probe. It deliberately keeps OpenAI out of the
loop so that TMLL/Trace Server results can be compared with Trace Compass's
Java KernelThreadInformationProvider results.
"""

from __future__ import annotations

import argparse
import datetime
import json
import time
import math
import re
import sys
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd


PROBE_BUILD_ID = "2026-07-29-syscall-latency-v1"


STATE_ALIASES = {
    "RUN": "RUNNING_USER_MODE",
    "RUNNING": "RUNNING_USER_MODE",
    "USERMODE": "RUNNING_USER_MODE",
    "USER MODE": "RUNNING_USER_MODE",
    "RUN USERMODE": "RUNNING_USER_MODE",
    "RUN USER MODE": "RUNNING_USER_MODE",
    "RUN_SYTEMCALL": "RUNNING_SYSTEM_CALL",
    "SYSCALL": "RUNNING_SYSTEM_CALL",
    "SYSTEM CALL": "RUNNING_SYSTEM_CALL",
    "RUN SYSTEMCALL": "RUNNING_SYSTEM_CALL",
    "RUN SYSTEM CALL": "RUNNING_SYSTEM_CALL",
    "WAIT_CPU": "RUNNABLE_WAITING_FOR_CPU",
    "WAIT CPU": "RUNNABLE_WAITING_FOR_CPU",
    "WAIT FOR CPU": "RUNNABLE_WAITING_FOR_CPU",
    "WAITING FOR CPU": "RUNNABLE_WAITING_FOR_CPU",
    "RUNNABLE": "RUNNABLE_WAITING_FOR_CPU",
    "WAIT_BLOCKED": "BLOCKED",
    "WAIT BLOCKED": "BLOCKED",
    "WAITING BLOCKED": "BLOCKED",
    "INTERRUPTED": "INTERRUPTED",
    "WAIT_FORK": "WAITING_FOR_FORK",
    "WAIT FORK": "WAITING_FOR_FORK",
    "WAIT_UNKNOWN": "WAITING_UNKNOWN",
    "WAIT UNKNOWN": "WAITING_UNKNOWN",
    "NOT_ALIVE": "NOT_ALIVE",
    "NOT ALIVE": "NOT_ALIVE",
    "EXIT": "EXITED",
    "EXITED": "EXITED",
    "ZOMBIE": "ZOMBIE",
    "UNKNOWN": "UNKNOWN",
}


def normalized_token(value: Any) -> str:
    """Normalize a server-provided state/style token for comparisons."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return ""
    return re.sub(r"[^A-Z0-9]+", " ", str(value).upper()).strip()


def style_tokens(style: Any) -> list[str]:
    """Extract likely state names from a Trace Server output style."""
    if style is None or (isinstance(style, float) and math.isnan(style)):
        return []
    if isinstance(style, str):
        return [style]
    if not isinstance(style, dict):
        return [str(style)]

    preferred_keys = (
        "parentKey",
        "parent_key",
        "parent",
        "styleName",
        "style_name",
        "name",
        "label",
    )
    result: list[str] = []
    for key in preferred_keys:
        if key in style and style[key] is not None:
            result.extend(style_tokens(style[key]))
    for key in ("values", "properties"):
        nested = style.get(key)
        if isinstance(nested, dict):
            result.extend(style_tokens(nested))
    return result


def canonical_state(label: Any, style: Any = None) -> str:
    """Convert a Thread Status style/label to a stable scheduling state.

    In this provider, ``label`` is normally a syscall name. The actual
    scheduling state is carried by the state's output style.
    """
    tokens = [normalized_token(token) for token in style_tokens(style)]
    tokens = [token for token in tokens if token]

    for token in tokens:
        if "NOT ALIVE" in token:
            return "NOT_ALIVE"
        if "WAIT" in token and "BLOCK" in token:
            return "BLOCKED"
        if "WAIT" in token and "CPU" in token:
            return "RUNNABLE_WAITING_FOR_CPU"
        if "RUNNABLE" in token:
            return "RUNNABLE_WAITING_FOR_CPU"
        if "SYSCALL" in token or "SYSTEM CALL" in token:
            return "RUNNING_SYSTEM_CALL"
        if "USERMODE" in token or "USER MODE" in token:
            return "RUNNING_USER_MODE"
        if "RUNNING" in token or token == "RUN":
            return (
                "RUNNING_SYSTEM_CALL"
                if normalized_token(label)
                else "RUNNING_USER_MODE"
            )
        if "INTERRUPT" in token:
            return "INTERRUPTED"
        if "FORK" in token:
            return "WAITING_FOR_FORK"
        if "ZOMBIE" in token:
            return "ZOMBIE"
        if "EXIT" in token:
            return "EXITED"

    # Compatibility fallback for servers that put state names in the label.
    normalized = normalized_token(label)
    return STATE_ALIASES.get(normalized, "UNKNOWN")


def summarize_thread_rows(rows: pd.DataFrame, tid: int) -> dict[str, Any]:
    """Summarize already-filtered TIME_GRAPH rows for a single thread."""
    required = {
        "entry_id",
        "entry_name",
        "start_time",
        "end_time",
        "label",
        "style",
        "value",
    }
    missing = required.difference(rows.columns)
    if missing:
        raise ValueError(f"TMLL data is missing columns: {sorted(missing)}")

    clean = rows.copy()
    clean["start_time"] = pd.to_numeric(clean["start_time"], errors="coerce")
    clean["end_time"] = pd.to_numeric(clean["end_time"], errors="coerce")
    clean = clean.dropna(subset=["start_time", "end_time"])
    clean = clean[clean["end_time"] > clean["start_time"]]
    clean = clean.drop_duplicates(
        subset=["entry_id", "start_time", "end_time", "label", "style_key", "value"]
    ).sort_values(["start_time", "end_time"])

    totals: dict[str, int] = defaultdict(int)
    intervals: list[dict[str, Any]] = []
    for row in clean.itertuples(index=False):
        start = int(row.start_time)
        end = int(row.end_time)
        duration = end - start
        state = canonical_state(row.label, row.style)
        totals[state] += duration
        intervals.append(
            {
                "state": state,
                "trace_server_label": None if pd.isna(row.label) else str(row.label),
                "trace_server_value": (
                    None if pd.isna(row.value) else row.value
                ),
                "trace_server_style": row.style,
                "start_timestamp_ns": start,
                "end_timestamp_exclusive_ns": end,
                "duration_ns": duration,
            }
        )

    observed = sum(totals.values())
    active = observed - totals.get("NOT_ALIVE", 0)

    summary = []
    for state, duration in sorted(
        totals.items(), key=lambda item: item[1], reverse=True
    ):
        summary.append(
            {
                "state": state,
                "duration_ns": duration,
                "percentage_of_observed_range": (
                    duration * 100.0 / observed if observed else 0.0
                ),
                "percentage_of_active_lifetime": (
                    None
                    if state == "NOT_ALIVE" or not active
                    else duration * 100.0 / active
                ),
            }
        )

    return {
        "tid": tid,
        "total_observed_duration_ns": observed,
        "active_lifetime_ns": active,
        "total_interval_count": len(intervals),
        "state_summary": summary,
        "intervals": intervals,
    }


def parse_thread_entry_name(value: Any) -> tuple[str, int, int, int] | None:
    """Parse Trace Compass's ``name TID PID PPID`` thread-entry format."""
    match = re.fullmatch(
        r"\s*(?P<name>.*?)\s+(?P<tid>\d+)\s+(?P<pid>\d+)\s+(?P<ppid>\d+)\s*",
        str(value),
    )
    if match is None:
        return None
    return (
        match.group("name"),
        int(match.group("tid")),
        int(match.group("pid")),
        int(match.group("ppid")),
    )


def thread_rows(data: pd.DataFrame, tid: int) -> pd.DataFrame:
    """Find entries whose explicit TID field equals ``tid``."""
    names = data["entry_name"].fillna("").astype(str)
    unique_names = sorted(set(names[names.str.strip().ne("")].tolist()))
    parsed = [
        (entry_name, identity)
        for entry_name in unique_names
        if (identity := parse_thread_entry_name(entry_name)) is not None
    ]
    matching_names = {
        entry_name
        for entry_name, (_, entry_tid, _, _) in parsed
        if entry_tid == tid
    }

    if not matching_names:
        nearest = sorted(
            parsed,
            key=lambda item: (abs(item[1][1] - tid), item[1][1], item[0]),
        )[:15]
        nearest_names = [entry_name for entry_name, _ in nearest]
        python_names = [
            entry_name
            for entry_name, (process_name, _, _, _) in parsed
            if "python" in process_name.lower() or "django" in process_name.lower()
        ][:15]
        raise LookupError(
            f"TID {tid} is not present in this trace's Thread Status tree. "
            f"Closest available TIDs: {nearest_names}. "
            f"Python/Django entries: {python_names or 'none'}. "
            "The TID may belong to a different host trace."
        )

    direct = data[names.isin(matching_names)]
    entry_ids = set(direct["entry_id"].tolist())
    return data[data["entry_id"].isin(entry_ids)].copy()


def matching_thread_entry_ids(tree: Any, tid: int) -> tuple[set[int], dict[int, str]]:
    """Return Thread Status tree entry IDs whose explicit TID equals ``tid``."""
    names_by_id = {
        int(node.id): str(node.name)
        for node in tree.nodes
        if getattr(node, "id", None) is not None
    }
    parsed = [
        (entry_id, entry_name, identity)
        for entry_id, entry_name in names_by_id.items()
        if (identity := parse_thread_entry_name(entry_name)) is not None
    ]
    matching = {
        entry_id
        for entry_id, _, (_, entry_tid, _, _) in parsed
        if entry_tid == tid
    }
    if matching:
        return matching, names_by_id

    nearest = sorted(
        parsed,
        key=lambda item: (abs(item[2][1] - tid), item[2][1], item[1]),
    )[:15]
    python_names = [
        entry_name
        for _, entry_name, (process_name, _, _, _) in parsed
        if "python" in process_name.lower() or "django" in process_name.lower()
    ][:15]
    raise LookupError(
        f"TID {tid} is not present in this trace's Thread Status tree. "
        f"Closest available TIDs: {[name for _, name, _ in nearest]}. "
        f"Python/Django entries: {python_names or 'none'}. "
        "The TID may belong to a different host trace."
    )


def fetch_raw_thread_states(
    client: Any,
    experiment: Any,
    output_id: str,
    tree: Any,
    tid: int,
    start: int,
    end: int,
    resolution: str,
    strategy: str,
) -> pd.DataFrame:
    """Fetch raw TIME_GRAPH states without dropping their value or style."""
    from tmll.tsp.tsp.tsp_client import TspClient

    entry_ids, names_by_id = matching_thread_entry_ids(tree, tid)
    records: list[dict[str, Any]] = []
    intervals = client._calculate_intervals(start, end, resolution)
    for interval_start, interval_end, num_times in intervals:
        parameters = {
            TspClient.PARAMETERS_KEY: {
                TspClient.REQUESTED_ITEM_KEY: sorted(entry_ids),
                TspClient.REQUESTED_TIME_RANGE_KEY: {
                    TspClient.REQUESTED_TIME_RANGE_START_KEY: interval_start,
                    TspClient.REQUESTED_TIME_RANGE_END_KEY: interval_end,
                    TspClient.REQUESTED_TIME_RANGE_NUM_TIMES_KEY: num_times,
                },
                "filter_query_parameters": {"strategy": strategy},
            }
        }
        response = client.tsp_client.fetch_timegraph_states(
            exp_uuid=experiment.uuid,
            output_id=output_id,
            parameters=parameters,
        )
        if response.status_code != 200 or response.model.model is None:
            raise RuntimeError(
                "Failed to fetch raw Thread Status states: "
                f"{response.status_code} {response.status_text}"
            )

        for row in response.model.model.rows:
            if int(row.entry_id) not in entry_ids:
                continue
            for state in row.states:
                raw_style = getattr(state, "style", None)
                records.append(
                    {
                        "entry_id": int(row.entry_id),
                        "entry_name": names_by_id.get(int(row.entry_id)),
                        "start_time": state.start_time,
                        "end_time": state.end_time,
                        "label": getattr(state, "label", None),
                        "value": getattr(state, "value", None),
                        "style": raw_style,
                        "style_key": json.dumps(
                            raw_style, sort_keys=True, default=str
                        ),
                    }
                )
    return pd.DataFrame.from_records(
        records,
        columns=[
            "entry_id",
            "entry_name",
            "start_time",
            "end_time",
            "label",
            "value",
            "style",
            "style_key",
        ],
    )


def load_existing_experiment(client: Any, experiment_id: str) -> Any:
    """Load an already-open Trace Server experiment by UUID."""
    from tmll.common.models.experiment import Experiment

    response = client.tsp_client.fetch_experiment(experiment_id)
    if response.status_code != 200:
        raise RuntimeError(
            f"Trace Server could not load experiment {experiment_id}: "
            f"{response.status_code} {response.status_text}"
        )
    experiment = Experiment.from_tsp_experiment(response.model)
    experiment.assign_outputs(client._fetch_outputs(experiment))
    return experiment


class TraceServerSession:
    """One Trace Server client and loaded experiment, reused across calls.

    Before this, every table page (1,000 rows) and every fetch created a new
    TMLLClient, health-checked the server, re-fetched the experiment and all
    of its outputs, and re-fetched the table's columns -- thousands of times
    for one large syscall-table scan. Output trees and table columns are
    cached here too; none of them change while the trace is unchanged.
    """

    def __init__(self, client: Any, experiment: Any) -> None:
        self.client = client
        self.experiment = experiment
        self.table_columns: dict[str, list[dict[str, Any]]] = {}
        self.trees: dict[str, Any] = {}

    def output_tree(self, output_id: str) -> Any:
        tree = self.trees.get(output_id)
        if tree is None:
            outputs_with_tree = self.client.fetch_outputs_with_tree(
                self.experiment, custom_output_ids=[output_id]
            )
            if not outputs_with_tree:
                raise RuntimeError(f"Could not fetch the tree for output {output_id}")
            tree = outputs_with_tree[0]["tree"]
            self.trees[output_id] = tree
        return tree


_SESSIONS: dict[tuple[str, int, str], TraceServerSession] = {}
_SESSIONS_LOCK = threading.Lock()


def get_session(host: str, port: int, experiment_id: str) -> TraceServerSession:
    """Return the reusable session for an experiment, creating it once.

    A session is only kept once the experiment has finished indexing:
    while it is still indexing, its start/end and outputs are partial and
    must be re-read on the next call.
    """
    key = (host, port, experiment_id)
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(key)
    if session is not None:
        return session

    try:
        from tmll.tmll_client import TMLLClient
    except ImportError as exc:
        raise RuntimeError(
            "TMLL is not installed in this Python environment. Install TMLL "
            "from its source checkout, activate that environment, and retry."
        ) from exc

    client = TMLLClient(
        tsp_server_host=host,
        tsp_server_port=port,
        install_tsp_server=False,
        verbose=False,
    )
    if getattr(client, "health_status", None) != 200:
        raise RuntimeError(f"Trace Server is not healthy at http://{host}:{port}")

    session = TraceServerSession(client, load_existing_experiment(client, experiment_id))
    if str(getattr(session.experiment, "indexing", "")).upper() != "RUNNING":
        with _SESSIONS_LOCK:
            _SESSIONS[key] = session
    return session


def drop_session(host: str, port: int, experiment_id: str) -> None:
    with _SESSIONS_LOCK:
        _SESSIONS.pop((host, port, experiment_id), None)


def list_experiment_outputs(
    host: str,
    port: int,
    experiment_id: str,
) -> dict[str, Any]:
    """List the Trace Server outputs available for an existing experiment."""
    experiment = get_session(host, port, experiment_id).experiment
    outputs = [
        {
            "id": str(output.id),
            "name": str(output.name),
            "type": str(output.type),
            "description": (
                None
                if getattr(output, "description", None) is None
                else str(output.description)
            ),
        }
        for output in experiment.outputs
    ]
    outputs.sort(key=lambda item: (item["name"].lower(), item["id"].lower()))

    return {
        "experiment_id": experiment.uuid,
        "experiment_name": experiment.name,
        "outputs": outputs,
        "output_count": len(outputs),
    }


def _fetch_table_columns(client: Any, experiment: Any, selected: Any) -> list[dict[str, Any]]:
    column_response = client.tsp_client.fetch_virtual_table_columns(
        exp_uuid=experiment.uuid,
        output_id=selected.id,
    )
    if (
        column_response.status_code != 200
        or column_response.model.model is None
    ):
        raise RuntimeError(
            "Failed to fetch virtual-table columns: "
            f"{column_response.status_code} {column_response.status_text}"
        )
    return [
        {
            "id": int(column.id),
            "name": str(column.name),
            "description": (
                None
                if getattr(column, "description", None) is None
                else str(column.description)
            ),
            "type": (
                None
                if getattr(column, "type", None) is None
                else str(column.type)
            ),
        }
        for column in column_response.model.model.columns
    ]


def fetch_table_sample(
    host: str,
    port: int,
    experiment_id: str,
    output_id: str,
    start_index: int = 0,
    line_count: int = 20,
    search_direction: str = "NEXT",
) -> dict[str, Any]:
    """Fetch one page from a Trace Server virtual-table output."""
    try:
        from tmll.common.models.data.table.table import TableData
        from tmll.tsp.tsp.tsp_client import TspClient
    except ImportError as exc:
        raise RuntimeError(
            "TMLL is not installed in this Python environment. Install TMLL "
            "from its source checkout, activate that environment, and retry."
        ) from exc

    session = get_session(host, port, experiment_id)
    client = session.client
    experiment = session.experiment
    selected = next(
        (
            output
            for output in experiment.outputs
            if str(output.id) == output_id
        ),
        None,
    )
    if selected is None:
        raise LookupError(
            f"Output {output_id!r} is not available in experiment {experiment_id}"
        )
    if str(selected.type).upper() != "TABLE":
        raise ValueError(
            f"Output {output_id!r} has type {selected.type}, not TABLE"
        )

    columns = session.table_columns.get(str(selected.id))
    if columns is None:
        columns = _fetch_table_columns(client, experiment, selected)
        session.table_columns[str(selected.id)] = columns
    column_ids = [column["id"] for column in columns]

    parameters = {
        TspClient.PARAMETERS_KEY: {
            TspClient.REQUESTED_TABLE_LINE_INDEX_KEY: start_index,
            TspClient.REQUESTED_TABLE_LINE_COUNT_KEY: line_count,
            TspClient.REQUESTED_TABLE_LINE_COLUMN_IDS_KEY: column_ids,
            TspClient.REQUESTED_TABLE_LINE_SEACH_DIRECTION_KEY: search_direction,
        }
    }
    line_response = client.tsp_client.fetch_virtual_table_lines(
        exp_uuid=experiment.uuid,
        output_id=selected.id,
        parameters=parameters,
    )
    if line_response.status_code != 200 or line_response.model.model is None:
        raise RuntimeError(
            "Failed to fetch virtual-table rows: "
            f"{line_response.status_code} {line_response.status_text}"
        )

    table = TableData.from_tsp_table(line_response.model.model)
    returned_column_ids = [int(column_id) for column_id in table.columns]
    names_by_id = {
        int(column["id"]): str(column["name"])
        for column in columns
    }
    returned_names = [
        names_by_id.get(column_id, f"Column {column_id}")
        for column_id in returned_column_ids
    ]

    rows = []
    for row in table.rows:
        values = list(row.values)
        rows.append(
            {
                "index": getattr(row, "index", None),
                "values": {
                    returned_names[index]: value
                    for index, value in enumerate(values)
                    if index < len(returned_names)
                },
            }
        )

    return {
        "experiment_id": experiment.uuid,
        "experiment_name": experiment.name,
        "output": {
            "id": str(selected.id),
            "name": str(selected.name),
            "type": str(selected.type),
        },
        "columns": columns,
        "start_index": start_index,
        "requested_line_count": line_count,
        "returned_line_count": len(rows),
        "rows": rows,
    }


_SYSCALL_LATENCY_OUTPUT_ID = (
    "org.eclipse.tracecompass.analysis.timing.core.segmentstore."
    "SegmentStoreTableDataProvider:"
    "org.eclipse.tracecompass.analysis.os.linux.latency.syscall"
)

_FUTEX_OUTPUT_ID = (
    "org.eclipse.tracecompass.analysis.timing.core.segmentstore."
    "SegmentStoreTableDataProvider:lttng.analysis.futex"
)


def _integer(value: Any) -> int:
    return int(str(value).strip().replace(",", ""))


def _normalize_syscall_row(row: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    values = row.get("values", {})
    try:
        row_tid = _integer(values.get("TID"))
        start_ns = _integer(values.get("Timestamp ns"))
        duration_ns = _integer(values.get("Duration"))
    except (TypeError, ValueError):
        return None
    return row_tid, {
        "table_index": row.get("index"),
        "start_timestamp_ns": start_ns,
        "end_timestamp_exclusive_ns": start_ns + duration_ns,
        "duration_ns": duration_ns,
        "duration_ms": round(duration_ns / 1_000_000.0, 3),
        "system_call": values.get("System Call"),
        "return_value": values.get("Return value"),
        "component": values.get("Component"),
        "file": values.get("File"),
    }


def _normalize_futex_row(row: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    values = row.get("values", {})
    match = _FUTEX_CONTENT_PATTERN.search(str(values.get("Content", "")))
    if match is None:
        return None
    try:
        row_tid = int(match.group("tid"))
        start_ns = _integer(values.get("Timestamp ns"))
        duration_ns = _integer(values.get("Duration"))
    except (TypeError, ValueError):
        return None
    return row_tid, {
        "table_index": row.get("index"),
        "start_timestamp_ns": start_ns,
        "end_timestamp_exclusive_ns": start_ns + duration_ns,
        "duration_ns": duration_ns,
        "duration_ms": round(duration_ns / 1_000_000.0, 3),
        "event_type": values.get("Name"),
        "futex_uaddr": match.group("uaddr"),
        "thread_name": match.group("name"),
        "trace": values.get("Trace"),
    }


def _rows_for_tid(
    host: str,
    port: int,
    experiment_id: str,
    tid: int,
    output_id: str,
    kind: str,
    normalize: Any,
    max_rows: int,
    page_size: int,
    cache: Any,
    fingerprint: str | None,
) -> dict[str, Any]:
    """Scan a Trace Server table and return one TID's normalized rows.

    The table has no server-side TID filter, so finding one thread's rows
    means scanning the whole table. With a cache, that scan happens once per
    trace: every thread's rows are stored as the pages stream in, and later
    calls for any TID read them back instead of rescanning.
    """
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    if not 1 <= page_size <= 1_000:
        raise ValueError("page_size must be between 1 and 1000")

    use_cache = cache is not None and cache.enabled and fingerprint is not None
    if use_cache:
        hit = cache.table_rows_for_tid(fingerprint, kind, tid, max_rows)
        if hit is not None:
            return _table_result(
                output_id, hit["scanned_rows"], hit["scan_complete"],
                max_rows, hit["rows"], from_cache=True,
            )

    writer = cache.begin_table_scan(fingerprint, kind) if use_cache else None
    scanned_rows = 0
    start_index = 0
    matching_rows: list[dict[str, Any]] = []
    scan_complete = False

    try:
        while scanned_rows < max_rows:
            requested = min(page_size, max_rows - scanned_rows)
            page = fetch_table_sample(
                host=host,
                port=port,
                experiment_id=experiment_id,
                output_id=output_id,
                start_index=start_index,
                line_count=requested,
                search_direction="NEXT",
            )
            rows = page.get("rows", [])
            returned = len(rows)

            batch = []
            for row in rows:
                normalized = normalize(row)
                if normalized is None:
                    continue
                batch.append(normalized)
                if normalized[0] == tid:
                    matching_rows.append(normalized[1])
            if writer is not None:
                writer.add(batch)

            scanned_rows += returned
            if returned < requested:
                scan_complete = True
                break
            start_index += returned
    except BaseException:
        if writer is not None:
            writer.abort()
        raise

    if writer is not None:
        writer.finish(scanned_rows, scan_complete, max_rows)

    return _table_result(
        output_id, scanned_rows, scan_complete, max_rows, matching_rows,
        from_cache=False,
    )


def _table_result(
    output_id: str,
    scanned_rows: int,
    scan_complete: bool,
    max_rows: int,
    rows: list[dict[str, Any]],
    from_cache: bool,
) -> dict[str, Any]:
    rows = sorted(
        rows,
        key=lambda row: (int(row["start_timestamp_ns"]), int(row["duration_ns"])),
    )
    return {
        "provider_id": output_id,
        "scanned_rows": scanned_rows,
        "scan_complete": scan_complete,
        "max_rows": max_rows,
        "matching_tid_row_count": len(rows),
        "rows": rows,
        "from_cache": from_cache,
    }


def fetch_syscall_latency_rows_for_tid(
    host: str,
    port: int,
    experiment_id: str,
    tid: int,
    max_rows: int = 200_000,
    page_size: int = 1_000,
    cache: Any = None,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    """Return one TID's rows from the syscall-latency table (see _rows_for_tid)."""
    return _rows_for_tid(
        host, port, experiment_id, tid, _SYSCALL_LATENCY_OUTPUT_ID,
        "syscall_latency", _normalize_syscall_row, max_rows, page_size,
        cache, fingerprint,
    )


_FUTEX_CONTENT_PATTERN = re.compile(
    r"uaddr=(?P<uaddr>\S+?),\s*name=(?P<name>.*?),\s*thread=(?P<tid>\d+)\s*$"
)


def fetch_futex_contention_rows_for_tid(
    host: str,
    port: int,
    experiment_id: str,
    tid: int,
    max_rows: int = 200_000,
    page_size: int = 1_000,
    cache: Any = None,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    """Return one TID's rows from the futex-contention table.

    Unlike the syscall-latency table this one has no TID column: the thread
    ID, lock address and thread name are packed into a "Content" string
    (e.g. "uaddr=34440084, name=rs:main Q:Reg, thread=454"), which
    _normalize_futex_row parses. Each row's "Name" is WAIT, WAKE or WAKE_OP:
    WAIT is time a thread spent blocked on the futex; WAKE/WAKE_OP are the
    (near-instant) wake operations another thread performed on it.
    """
    return _rows_for_tid(
        host, port, experiment_id, tid, _FUTEX_OUTPUT_ID,
        "futex_contention", _normalize_futex_row, max_rows, page_size,
        cache, fingerprint,
    )


_EVENTS_TABLE_OUTPUT_ID = (
    "org.eclipse.tracecompass.internal.provisional.tmf.core.model."
    "events.TmfEventTableDataProvider"
)

_INET_SOCK_CONTENT_PATTERN = re.compile(
    r"seq=(?P<seq>0x[0-9a-fA-F]+),\s*ack_seq=(?P<ack_seq>0x[0-9a-fA-F]+),"
    r".*?flags=(?P<flags>0x[0-9a-fA-F]+)"
)

_TIMESTAMP_DISPLAY_PATTERN = re.compile(
    r"^(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\.(?P<frac>[\d ]+)$"
)


def _parse_display_timestamp_to_ns(
    display: str,
    reference_date: datetime.date,
) -> int:
    """Convert a TSP Events Table "HH:MM:SS.nnn nnn nnn" cell into epoch ns.

    The Trace Server renders event timestamps in the SERVER'S OWN LOCAL
    TIMEZONE, not UTC and not trace-relative time -- confirmed empirically:
    reconstructing datetime.fromtimestamp(experiment_start_ns / 1e9) in the
    local timezone this Python process runs in reproduces the displayed
    wall-clock hour/minute/second exactly. This function therefore assumes
    the caller runs in the same timezone as the Trace Server (true here --
    both run on the same host) and that the queried range does not cross a
    local-midnight rollover (true for this ~14s trace).
    """
    match = _TIMESTAMP_DISPLAY_PATTERN.match(display.strip())
    if match is None:
        raise ValueError(f"Unrecognized timestamp display format: {display!r}")

    nanosecond_fraction = int(match.group("frac").replace(" ", ""))
    naive = datetime.datetime(
        reference_date.year,
        reference_date.month,
        reference_date.day,
        int(match.group("h")),
        int(match.group("m")),
        int(match.group("s")),
    )
    return int(naive.timestamp()) * 1_000_000_000 + nanosecond_fraction


_INET_SOCK_SCAN_WINDOW_MARGIN_NS = 50_000_000  # 50 ms


def fetch_inet_sock_local_events(
    host: str,
    port: int,
    experiment_id: str,
    start_ns: int | None = None,
    end_ns: int | None = None,
    max_matches: int = 20_000,
) -> dict[str, Any]:
    """Scan the raw Events Table for inet_sock_local_in/out events.

    Trace Compass ships a generic analysis (EventMatchingLatencyAnalysis)
    that does exactly this matching already, but its registration does not
    attach to this combined multi-trace experiment (its tracetype names
    TmfExperiment directly rather than a constituent-trace interface with
    applies_experiment=true, the pattern OsExecutionGraph uses successfully
    -- confirmed by tracing TmfAnalysisModuleHelperConfigElement's own
    matching logic, and independently confirmed absent from the
    experiment's own Analysis folder in the Trace Compass UI). This
    fetches the same underlying raw events
    (inet_sock_local_in/inet_sock_local_out, the LTTng "addons" module's
    TCP tracepoints) directly instead, so the matching can be done in
    Python. See match_cross_host_tcp_events() in
    tmll_assistant_service_syscall_v1.py for the matching step, and
    heuristic_summary.md for the full investigation.

    Rather than scanning the full multi-million-row Events Table linearly,
    this uses the Trace Server's virtual-table search
    (table_search_expressions): each search call jumps directly to the
    next row whose "Event type" column matches the given regex and returns
    its real table index, so the next search can resume from index + 1.
    Confirmed empirically to be fast (~15 matches in ~1.4s) versus what
    would otherwise be an impractically slow full linear scan of a ~2.2M
    event table to find a comparatively small number of matching rows.

    If start_ns/end_ns are given, this also uses the table's requested_times
    positioning to jump straight to the row nearest start_ns (minus a small
    margin) instead of starting the search from index 0, and stops once a
    match's timestamp passes end_ns plus the same margin -- narrowing the
    scan to roughly one thread's active window instead of the whole
    multi-host trace. The margin exists because a matched pair's two halves
    (the local send and the remote receive) can be a few milliseconds apart
    in real time even on synchronized clocks; omitting it risks cutting off
    the far side of a message whose triggering syscall sits right at the
    edge of the window.
    """
    try:
        from tmll.tmll_client import TMLLClient
        from tmll.tsp.tsp.tsp_client import TspClient
    except ImportError as exc:
        raise RuntimeError(
            "TMLL is not installed in this Python environment. Install TMLL "
            "from its source checkout, activate that environment, and retry."
        ) from exc

    if max_matches < 1:
        raise ValueError("max_matches must be positive")

    client = get_session(host, port, experiment_id).client

    experiments_response = client.tsp_client.fetch_experiments()
    experiment_summary = next(
        (
            exp
            for exp in experiments_response.model.experiments
            if exp.UUID == experiment_id
        ),
        None,
    )
    if experiment_summary is None:
        raise LookupError(f"Experiment {experiment_id!r} not found")

    reference_date = datetime.datetime.fromtimestamp(
        experiment_summary.start / 1_000_000_000
    ).date()

    columns_response = client.tsp_client.fetch_virtual_table_columns(
        exp_uuid=experiment_id,
        output_id=_EVENTS_TABLE_OUTPUT_ID,
    )
    if columns_response.status_code != 200 or columns_response.model.model is None:
        raise RuntimeError(
            "Failed to fetch Events Table columns: "
            f"{columns_response.status_code} {columns_response.status_text}"
        )

    columns = columns_response.model.model.columns
    column_ids = [column.id for column in columns]
    name_by_id = {column.id: column.name for column in columns}
    event_type_column_id = next(
        (column.id for column in columns if column.name == "Event type"),
        None,
    )
    if event_type_column_id is None:
        raise RuntimeError('Events Table has no "Event type" column')

    window_end_ns = (
        end_ns + _INET_SOCK_SCAN_WINDOW_MARGIN_NS
        if end_ns is not None
        else None
    )

    next_index = 0
    if start_ns is not None:
        window_start_ns = max(0, start_ns - _INET_SOCK_SCAN_WINDOW_MARGIN_NS)
        position_parameters = {
            TspClient.PARAMETERS_KEY: {
                TspClient.REQUESTED_TIME_KEY: [window_start_ns],
                TspClient.REQUESTED_TABLE_LINE_COUNT_KEY: 1,
                TspClient.REQUESTED_TABLE_LINE_COLUMN_IDS_KEY: column_ids,
            }
        }
        position_response = client.tsp_client.fetch_virtual_table_lines(
            exp_uuid=experiment_id,
            output_id=_EVENTS_TABLE_OUTPUT_ID,
            parameters=position_parameters,
        )
        if (
            position_response.status_code == 200
            and position_response.model.model.lines
        ):
            next_index = position_response.model.model.lines[0].index

    matches: list[dict[str, Any]] = []
    scan_complete = False

    while len(matches) < max_matches:
        parameters = {
            TspClient.PARAMETERS_KEY: {
                TspClient.REQUESTED_TABLE_LINE_INDEX_KEY: next_index,
                TspClient.REQUESTED_TABLE_LINE_COUNT_KEY: 1,
                TspClient.REQUESTED_TABLE_LINE_COLUMN_IDS_KEY: column_ids,
                TspClient.REQUESTED_TABLE_LINE_SEACH_DIRECTION_KEY: "NEXT",
                TspClient.REQUESTED_TABLE_LINE_SEARCH_EXPRESSION_KEY: {
                    str(event_type_column_id): "inet_sock_local_.*"
                },
            }
        }
        response = client.tsp_client.fetch_virtual_table_lines(
            exp_uuid=experiment_id,
            output_id=_EVENTS_TABLE_OUTPUT_ID,
            parameters=parameters,
        )
        if response.status_code != 200 or not response.model.model.lines:
            scan_complete = True
            break

        line = response.model.model.lines[0]
        values = {
            name_by_id[column_id]: cell.content
            for column_id, cell in zip(column_ids, line.cells)
        }

        content_match = _INET_SOCK_CONTENT_PATTERN.search(
            str(values.get("Contents", ""))
        )
        if content_match is None:
            next_index = line.index + 1
            continue

        try:
            timestamp_ns = _parse_display_timestamp_to_ns(
                str(values.get("Timestamp", "")),
                reference_date,
            )
        except ValueError:
            next_index = line.index + 1
            continue

        if window_end_ns is not None and timestamp_ns > window_end_ns:
            scan_complete = True
            break

        matches.append(
            {
                "table_index": line.index,
                "trace": values.get("Trace"),
                "event_type": values.get("Event type"),
                "timestamp_ns": timestamp_ns,
                "seq": int(content_match.group("seq"), 16),
                "ack_seq": int(content_match.group("ack_seq"), 16),
                "flags": int(content_match.group("flags"), 16),
            }
        )
        next_index = line.index + 1

    return {
        "output_id": _EVENTS_TABLE_OUTPUT_ID,
        "max_matches": max_matches,
        "scan_complete": scan_complete,
        "event_count": len(matches),
        "events": matches,
    }


def select_thread_status_output(experiment: Any) -> Any | None:
    """Select the Linux thread-status time graph behind Control Flow.

    Trace Server versions do not use one stable display name for this output.
    Depending on the server/product, the same provider can appear as either
    ``Control Flow`` or ``Thread Status``.
    """
    candidates = [
        output
        for output in experiment.outputs
        if str(output.type).upper() == "TIME_GRAPH"
    ]

    provider_suffix = "threadstatus.ThreadStatusDataProvider"
    for output in candidates:
        if provider_suffix.lower() in str(output.id).lower():
            return output

    accepted_names = {"control flow", "thread status"}
    for output in candidates:
        if str(output.name).strip().lower() in accepted_names:
            return output

    return None


def fetch_control_flow(
    host: str,
    port: int,
    tid: int,
    experiment_id: str | None,
    trace_paths: list[str] | None,
    experiment_name: str,
    start: int | None,
    end: int | None,
    resolution: str,
) -> dict[str, Any]:
    """Connect to Trace Server, fetch Control Flow, and summarize one TID."""
    try:
        from tmll.tmll_client import TMLLClient
    except ImportError as exc:
        raise RuntimeError(
            "TMLL is not installed in this Python environment. Install TMLL "
            "from its source checkout, activate that environment, and retry."
        ) from exc

    session = None
    if experiment_id:
        session = get_session(host, port, experiment_id)
        client = session.client
        experiment = session.experiment
    else:
        client = TMLLClient(
            tsp_server_host=host,
            tsp_server_port=port,
            install_tsp_server=False,
            verbose=True,
        )
        if getattr(client, "health_status", None) != 200:
            raise RuntimeError(f"Trace Server is not healthy at http://{host}:{port}")
        if not trace_paths:
            raise ValueError("At least one --trace path is required.")
        traces = [
            {"path": path, "name": Path(path).name}
            for path in trace_paths
        ]
        experiment = client.create_experiment(
            traces=traces,
            experiment_name=experiment_name,
        )
        if experiment is None:
            raise RuntimeError(
                f"Could not create experiment from {len(trace_paths)} trace path(s)"
            )

    selected = select_thread_status_output(experiment)
    if selected is None:
        available = [
            {"id": output.id, "name": output.name, "type": output.type}
            for output in experiment.outputs
        ]
        raise LookupError(
            "No Linux Thread Status/Control Flow TIME_GRAPH output was found. "
            f"Available outputs: {json.dumps(available)}"
        )

    if session is not None:
        output_tree = session.output_tree(selected.id)
    else:
        outputs_with_tree = client.fetch_outputs_with_tree(
            experiment, custom_output_ids=[selected.id]
        )
        if not outputs_with_tree:
            raise RuntimeError(f"Could not fetch the tree for output {selected.id}")
        output_tree = outputs_with_tree[0]["tree"]
    output_data = fetch_raw_thread_states(
        client=client,
        experiment=experiment,
        output_id=selected.id,
        tree=output_tree,
        tid=tid,
        start=experiment.start if start is None else start,
        end=experiment.end if end is None else end,
        resolution=resolution,
        strategy="DEEP",
    )
    if output_data.empty and session is not None:
        # The session keeps the output's tree, and a tree fetched while the
        # Trace Server was still building the analysis can lack threads: drop
        # it and fetch the tree again, waiting up to a minute for the thread.
        for _attempt in range(12):
            session.trees.pop(selected.id, None)
            output_tree = session.output_tree(selected.id)
            output_data = fetch_raw_thread_states(
                client=client,
                experiment=experiment,
                output_id=selected.id,
                tree=output_tree,
                tid=tid,
                start=experiment.start if start is None else start,
                end=experiment.end if end is None else end,
                resolution=resolution,
                strategy="DEEP",
            )
            if not output_data.empty:
                break
            time.sleep(5)
    if output_data.empty:
        raise RuntimeError(f"No time-graph rows were returned for {selected.id}")

    result = summarize_thread_rows(output_data, tid)
    result.update(
        {
            "experiment_id": experiment.uuid,
            "experiment_name": experiment.name,
            "control_flow_output_id": selected.id,
            "control_flow_output_name": selected.name,
            "requested_resolution": resolution,
            "note": (
                "The probe reads raw Trace Server TIME_GRAPH state styles "
                "because TMLL's DataFrame conversion currently retains only "
                "the optional label. Results are still sampled; compare these "
                "totals with the exact Java state-system result before using "
                "them as diagnostic ground truth."
            ),
        }
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize one kernel thread from TMLL Control Flow data."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--experiment", help="Existing Trace Server experiment UUID")
    source.add_argument(
        "--trace",
        action="append",
        dest="traces",
        help=(
            "Kernel trace file or directory path. Repeat --trace to combine "
            "multiple CTF traces into one experiment."
        ),
    )
    parser.add_argument("--tid", type=int, required=True, help="Thread ID")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--name", default="tmll-control-flow-probe")
    parser.add_argument("--start", type=int, help="Absolute start timestamp in ns")
    parser.add_argument("--end", type=int, help="Absolute end timestamp in ns")
    parser.add_argument(
        "--resolution",
        default="100us",
        help="TMLL/Trace Server sampling resolution (default: 100us)",
    )
    parser.add_argument(
        "--max-intervals",
        type=int,
        default=250,
        help="Maximum detailed intervals written to JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = fetch_control_flow(
            host=args.host,
            port=args.port,
            tid=args.tid,
            experiment_id=args.experiment,
            trace_paths=args.traces,
            experiment_name=args.name,
            start=args.start,
            end=args.end,
            resolution=args.resolution,
        )
        intervals = result["intervals"]
        result["included_interval_count"] = min(len(intervals), args.max_intervals)
        result["intervals_truncated"] = len(intervals) > args.max_intervals
        result["intervals"] = intervals[: args.max_intervals]
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:  # CLI boundary: emit a concise actionable error.
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
