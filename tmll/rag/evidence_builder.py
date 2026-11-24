from collections import defaultdict
from typing import Any

from rag.schemas import TraceEvidence

# Human-readable descriptions of each extra_evidence_dispatch category, used
# to steer knowledge retrieval toward the right document even when the
# category's own *computed result* isn't available to Python yet.
#
# critical_path is the category this exists for: unlike futex_contention and
# disk_io (which already have strong, specific facts below -- wait times,
# byte counts -- that retrieve their matching docs well on their own),
# critical path is computed by Trace Compass's Java side *after* this
# retrieval step runs (see collectCriticalPathIfIndicated() in
# HelloWorldView.java), so Python never has its result (participant list,
# span) to work with. The category name itself is real data Python does
# have at retrieval time, though -- classify_dominant_syscalls() computes it
# before build_retrieval_query() runs -- so surfacing it here, in
# descriptive language rather than a raw enum value, is what actually lets
# critical_path.md be retrieved for these threads. Confirmed empirically:
# without this fact, critical_path.md did not appear in the top 8 results
# for a synthetic clone/wait4-heavy query at all.
_DISPATCH_CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "futex_contention": (
        "This thread's syscalls indicate futex/lock contention."
    ),
    "disk_io": "This thread's syscalls indicate file I/O activity.",
    "critical_path": (
        "This thread's syscalls match a worker-churn pattern (repeated "
        "process creation via clone/wait4/fork); critical path / "
        "dependency chain analysis across threads and hosts is indicated."
    ),
    "cross_host_messaging": (
        "This thread's syscalls indicate network communication "
        "(send/receive/connect/accept); cross-host TCP message matching "
        "is indicated to identify which other host it exchanged data "
        "with."
    ),
}


class EvidenceBuilder:
    @staticmethod
    def from_thread_analysis(result: dict[str, Any]) -> TraceEvidence:
        dominant_syscall_by_frequency, dominant_syscall_rate_per_sec = (
            EvidenceBuilder._dominant_syscall_by_frequency(result)
        )
        futex_wait_count, futex_total_wait_ms, futex_longest_wait_ms = (
            EvidenceBuilder._futex_contention(result)
        )
        disk_io_read_bytes, disk_io_write_bytes, disk_io_call_count = (
            EvidenceBuilder._disk_io(result)
        )
        (
            cross_host_message_count,
            cross_host_partner_hosts,
            cross_host_total_transit_ms,
        ) = EvidenceBuilder._cross_host_messaging(result)
        extra_evidence_category = EvidenceBuilder._extra_evidence_category(
            result
        )
        return TraceEvidence(
            tid=int(result["tid"]),
            process_name=str(result.get("process_name", "unknown")),
            blocked_ms=float(result["blocked_ms"]),
            runnable_ms=float(
                result.get("runnable_ms", result.get("waiting_for_cpu_ms", 0.0))
            ),
            user_mode_ms=float(result.get("user_mode_ms", 0.0)),
            system_call_ms=float(result.get("system_call_ms", 0.0)),
            running_ms=(
                float(result["running_ms"])
                if result.get("running_ms") is not None
                else None
            ),
            dominant_blocking_syscall=(
                result.get("dominant_blocking_syscall")
                or EvidenceBuilder._dominant_blocking_syscall(result)
            ),
            longest_blocked_interval_ms=(
                result.get("longest_blocked_interval_ms")
                if result.get("longest_blocked_interval_ms") is not None
                else EvidenceBuilder._longest_blocked_interval_ms(result)
            ),
            dominant_syscall_by_frequency=dominant_syscall_by_frequency,
            dominant_syscall_rate_per_sec=dominant_syscall_rate_per_sec,
            futex_wait_count=futex_wait_count,
            futex_total_wait_ms=futex_total_wait_ms,
            futex_longest_wait_ms=futex_longest_wait_ms,
            disk_io_read_bytes=disk_io_read_bytes,
            disk_io_write_bytes=disk_io_write_bytes,
            disk_io_call_count=disk_io_call_count,
            cross_host_message_count=cross_host_message_count,
            cross_host_partner_hosts=cross_host_partner_hosts,
            cross_host_total_transit_ms=cross_host_total_transit_ms,
            extra_evidence_category=extra_evidence_category,
        )

    @staticmethod
    def build_category_query(evidence: TraceEvidence) -> str | None:
        """A second, narrow retrieval query for just the dispatch category.

        Deliberately kept separate from build_retrieval_query(): folding
        this fact into that longer, multi-sentence query dilutes its
        signal in the embedding (confirmed empirically -- see
        KnowledgeRetriever.merge_by_distance()'s docstring), so it is
        searched for on its own and the results are merged in by the
        caller instead.
        """
        if not evidence.extra_evidence_category:
            return None
        return _DISPATCH_CATEGORY_DESCRIPTIONS.get(
            evidence.extra_evidence_category
        )

    @staticmethod
    def build_retrieval_query(
        question: str,
        evidence: TraceEvidence,
    ) -> str:
        facts = [
            question,
            f"Linux kernel thread {evidence.tid} ({evidence.process_name}).",
            f"Blocked for {evidence.blocked_ms:.3f} ms.",
            f"Runnable for {evidence.runnable_ms:.3f} ms.",
        ]

        if evidence.dominant_blocking_syscall:
            facts.append(
                "Dominant blocking system call: "
                f"{evidence.dominant_blocking_syscall}."
            )

        if (
            evidence.dominant_syscall_by_frequency
            and evidence.dominant_syscall_rate_per_sec is not None
        ):
            facts.append(
                "Highest-frequency system call: "
                f"{evidence.dominant_syscall_by_frequency} at "
                f"{evidence.dominant_syscall_rate_per_sec:.1f} calls/sec."
            )

        if evidence.futex_wait_count:
            facts.append(
                "Futex contention: "
                f"{evidence.futex_wait_count} wait(s) totaling "
                f"{evidence.futex_total_wait_ms:.3f} ms, longest "
                f"{evidence.futex_longest_wait_ms:.3f} ms."
            )

        if evidence.disk_io_call_count:
            facts.append(
                "File I/O: "
                f"{evidence.disk_io_read_bytes} bytes read, "
                f"{evidence.disk_io_write_bytes} bytes written across "
                f"{evidence.disk_io_call_count} read/write/open calls."
            )

        if evidence.cross_host_message_count:
            facts.append(
                "Cross-host messaging: "
                f"{evidence.cross_host_message_count} matched TCP "
                f"message(s) with {evidence.cross_host_partner_hosts}, "
                f"totaling {evidence.cross_host_total_transit_ms:.3f} ms "
                "in network transit."
            )

        facts.append(
            "Interpret Linux thread states, system calls, Django socket "
            "behaviour, and relevant Trace Compass views."
        )
        return "\n".join(facts)

    @staticmethod
    def _longest_blocked_interval_ms(result: dict[str, Any]) -> float | None:
        intervals = result.get("longest_blocked_intervals") or []
        if not intervals:
            return None
        return float(intervals[0]["duration_ms"])

    @staticmethod
    def _dominant_blocking_syscall(result: dict[str, Any]) -> str | None:
        correlation = result.get("syscall_latency_correlation") or {}
        if not correlation.get("available"):
            return None

        duration_by_name: dict[str, float] = defaultdict(float)
        for item in correlation.get("correlations", []):
            for syscall in item.get("overlapping_syscalls", []):
                name = syscall.get("system_call") or syscall.get("name")
                if not name:
                    continue
                duration_by_name[str(name)] += float(
                    syscall.get("overlap_duration_ms", 0.0)
                )

        if not duration_by_name:
            return None
        return max(duration_by_name, key=duration_by_name.get)

    @staticmethod
    def _dominant_syscall_by_frequency(
        result: dict[str, Any],
    ) -> tuple[str | None, float | None]:
        frequency = result.get("syscall_frequency") or {}
        if not frequency.get("available"):
            return None, None

        by_syscall = frequency.get("by_syscall") or []
        if not by_syscall:
            return None, None

        top = by_syscall[0]
        name = top.get("system_call")
        rate = top.get("calls_per_second")
        return (
            str(name) if name else None,
            float(rate) if rate is not None else None,
        )

    @staticmethod
    def _futex_contention(
        result: dict[str, Any],
    ) -> tuple[int | None, float | None, float | None]:
        futex = result.get("futex_contention") or {}
        if not futex.get("available"):
            return None, None, None

        wait_count = futex.get("wait_count")
        if not wait_count:
            return None, None, None

        return (
            int(wait_count),
            float(futex.get("total_wait_ms", 0.0)),
            float(futex.get("longest_wait_ms", 0.0)),
        )

    @staticmethod
    def _disk_io(
        result: dict[str, Any],
    ) -> tuple[int | None, int | None, int | None]:
        disk_io = result.get("disk_io") or {}
        if not disk_io.get("available"):
            return None, None, None

        read_count = disk_io.get("read_call_count", 0)
        write_count = disk_io.get("write_call_count", 0)
        open_count = disk_io.get("open_call_count", 0)
        call_count = read_count + write_count + open_count
        if not call_count:
            return None, None, None

        return (
            int(disk_io.get("total_read_bytes", 0)),
            int(disk_io.get("total_write_bytes", 0)),
            int(call_count),
        )

    @staticmethod
    def _cross_host_messaging(
        result: dict[str, Any],
    ) -> tuple[int | None, str | None, float | None]:
        messaging = result.get("cross_host_messaging") or {}
        if not messaging.get("available"):
            return None, None, None

        message_count = messaging.get("message_count")
        if not message_count:
            return None, None, None

        partner_hosts = messaging.get("partner_hosts") or []
        return (
            int(message_count),
            ", ".join(partner_hosts) if partner_hosts else None,
            float(messaging.get("total_transit_ms", 0.0)),
        )

    @staticmethod
    def _extra_evidence_category(result: dict[str, Any]) -> str | None:
        dispatch = result.get("extra_evidence_dispatch") or {}
        category = dispatch.get("category")
        return str(category) if category else None
