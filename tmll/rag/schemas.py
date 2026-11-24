from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RetrievedDocument:
    text: str
    metadata: dict[str, Any]
    distance: float
    full_source_text: str | None = None


@dataclass(frozen=True)
class TraceEvidence:
    tid: int
    process_name: str
    blocked_ms: float
    runnable_ms: float
    user_mode_ms: float
    system_call_ms: float
    running_ms: float | None = None
    dominant_blocking_syscall: str | None = None
    longest_blocked_interval_ms: float | None = None
    dominant_syscall_by_frequency: str | None = None
    dominant_syscall_rate_per_sec: float | None = None
    futex_wait_count: int | None = None
    futex_total_wait_ms: float | None = None
    futex_longest_wait_ms: float | None = None
    disk_io_read_bytes: int | None = None
    disk_io_write_bytes: int | None = None
    disk_io_call_count: int | None = None
    cross_host_message_count: int | None = None
    cross_host_partner_hosts: str | None = None
    cross_host_total_transit_ms: float | None = None
    extra_evidence_category: str | None = None
