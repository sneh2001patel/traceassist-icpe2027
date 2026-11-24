#!/usr/bin/env python3
"""Small HTTP service that exposes TMLL analysis to Trace Compass Java."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tmll_control_flow_probe import fetch_control_flow, list_experiment_outputs


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
            self.send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        supported_paths = {
            "/analyze/thread",
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

            tid = int(request["tid"])
            resolution = str(request.get("resolution", "1us")).strip()
            max_blocked_intervals = int(
                request.get("max_blocked_intervals", 5)
            )

            if tid < 0:
                raise ValueError("tid must be non-negative")
            if not 1 <= max_blocked_intervals <= 20:
                raise ValueError(
                    "max_blocked_intervals must be between 1 and 20"
                )

            detailed = fetch_control_flow(
                host=self.server.trace_server_host,
                port=self.server.trace_server_port,
                tid=tid,
                experiment_id=experiment_id,
                trace_paths=None,
                experiment_name="unused-existing-experiment",
                start=None,
                end=None,
                resolution=resolution,
            )
            self.send_json(
                HTTPStatus.OK,
                {
                    "analysis": compact_thread_analysis(
                        detailed,
                        max_blocked_intervals=max_blocked_intervals,
                    )
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
