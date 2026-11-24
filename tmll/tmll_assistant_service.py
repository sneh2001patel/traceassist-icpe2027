#!/usr/bin/env python3
"""Small HTTP service that exposes TMLL analysis to Trace Compass Java."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from rag.evidence_builder import EvidenceBuilder
from rag.prompt_builder import PromptBuilder
from rag.retriever import KnowledgeRetriever
from tmll_control_flow_probe_syscall_v1 import (
    PROBE_BUILD_ID,
    fetch_control_flow,
    fetch_syscall_latency_rows_for_tid,
    fetch_table_sample,
    list_experiment_outputs,
)


SERVICE_BUILD_ID = "2026-08-04-rag-context-v1"
_RAG_RETRIEVER: KnowledgeRetriever | None = None


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


def analyze_thread(
    host: str,
    port: int,
    experiment_id: str,
    tid: int,
    resolution: str,
    max_blocked_intervals: int,
    max_syscall_table_rows: int,
) -> dict[str, Any]:
    """Fetch and compact thread evidence from the current trace experiment."""
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

    try:
        syscall_rows = fetch_syscall_latency_rows_for_tid(
            host=host,
            port=port,
            experiment_id=experiment_id,
            tid=tid,
            max_rows=max_syscall_table_rows,
        )
        analysis["syscall_latency_correlation"] = (
            correlate_blocked_intervals_with_syscalls(
                analysis["longest_blocked_intervals"],
                syscall_rows,
            )
        )
    except Exception as exc:
        analysis["syscall_latency_correlation"] = {
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

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path == "/health":
            self.send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
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
        supported_paths = {
            "/analyze/thread",
            "/answer/thread",
            "/experiment/output/table",
            "/experiment/outputs",
        }
        if self.path not in supported_paths:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(content_length))

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

            tid = int(request["tid"])
            resolution = str(request.get("resolution", "1us")).strip()
            max_blocked_intervals = int(
                request.get("max_blocked_intervals", 5)
            )
            max_syscall_table_rows = int(
                request.get("max_syscall_table_rows", 200_000)
            )

            if tid < 0:
                raise ValueError("tid must be non-negative")
            if not 1 <= max_blocked_intervals <= 20:
                raise ValueError(
                    "max_blocked_intervals must be between 1 and 20"
                )
            if not 1_000 <= max_syscall_table_rows <= 1_000_000:
                raise ValueError(
                    "max_syscall_table_rows must be between 1000 and 1000000"
                )

            analysis = analyze_thread(
                host=self.server.trace_server_host,
                port=self.server.trace_server_port,
                experiment_id=experiment_id,
                tid=tid,
                resolution=resolution,
                max_blocked_intervals=max_blocked_intervals,
                max_syscall_table_rows=max_syscall_table_rows,
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

                rag = build_thread_rag_response(
                    question=question,
                    analysis=analysis,
                    domain=rag_domain,
                    limit=rag_limit,
                )
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "analysis": analysis,
                        "rag": rag,
                    },
                )
                return

            self.send_json(
                HTTPStatus.OK,
                {
                    "analysis": analysis,
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Expose TMLL trace analysis through a local HTTP API."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--trace-server-host", default="localhost")
    parser.add_argument("--trace-server-port", type=int, default=8081)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = AnalysisServer((args.host, args.port), AnalysisHandler)
    server.trace_server_host = args.trace_server_host
    server.trace_server_port = args.trace_server_port

    print(
        f"TMLL assistant service: http://{args.host}:{args.port}\n"
        f"Trace Server: http://{args.trace_server_host}:"
        f"{args.trace_server_port}\n"
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
