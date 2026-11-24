from rag.schemas import RetrievedDocument, TraceEvidence


class PromptBuilder:
    @staticmethod
    def build(
        question: str,
        evidence: TraceEvidence,
        documents: list[RetrievedDocument],
    ) -> str:
        evidence_lines = [
            f"- Thread: {evidence.tid} ({evidence.process_name})",
            f"- Blocked: {evidence.blocked_ms:.3f} ms",
            f"- Runnable: {evidence.runnable_ms:.3f} ms",
        ]

        if evidence.running_ms is not None:
            evidence_lines.append(f"- Running: {evidence.running_ms:.3f} ms")
        if evidence.user_mode_ms:
            evidence_lines.append(f"- User mode: {evidence.user_mode_ms:.3f} ms")
        if evidence.system_call_ms:
            evidence_lines.append(
                f"- System calls: {evidence.system_call_ms:.3f} ms"
            )
        if evidence.dominant_blocking_syscall:
            evidence_lines.append(
                "- Dominant blocking syscall: "
                f"{evidence.dominant_blocking_syscall}"
            )
        if (
            evidence.dominant_syscall_by_frequency
            and evidence.dominant_syscall_rate_per_sec is not None
        ):
            evidence_lines.append(
                "- Highest-frequency syscall: "
                f"{evidence.dominant_syscall_by_frequency} "
                f"({evidence.dominant_syscall_rate_per_sec:.1f} calls/sec)"
            )
        if evidence.futex_wait_count:
            evidence_lines.append(
                "- Futex contention: "
                f"{evidence.futex_wait_count} wait(s), "
                f"{evidence.futex_total_wait_ms:.3f} ms total, "
                f"{evidence.futex_longest_wait_ms:.3f} ms longest"
            )
        if evidence.disk_io_call_count:
            evidence_lines.append(
                "- File I/O: "
                f"{evidence.disk_io_read_bytes} bytes read, "
                f"{evidence.disk_io_write_bytes} bytes written "
                f"({evidence.disk_io_call_count} read/write/open calls; "
                "file path not available)"
            )
        if evidence.longest_blocked_interval_ms is not None:
            evidence_lines.append(
                "- Longest blocked interval: "
                f"{evidence.longest_blocked_interval_ms:.3f} ms"
            )

        knowledge_sections = []
        for index, document in enumerate(documents, start=1):
            metadata = document.metadata
            body = document.full_source_text or document.text
            fetch_note = (
                " (full source fetched live for this answer)"
                if document.full_source_text
                else " (indexed summary only; live source unavailable)"
            )
            knowledge_sections.append(
                f"[{index}] {metadata['title']}{fetch_note}\n"
                f"{body}\n"
                f"Source: {metadata['source_url']}"
            )

        return f"""USER QUESTION
{question}

TRACE EVIDENCE
{chr(10).join(evidence_lines)}

RETRIEVED KNOWLEDGE
{chr(10).join(knowledge_sections)}

INSTRUCTIONS
1. Treat TRACE EVIDENCE as authoritative for this trace.
2. Use RETRIEVED KNOWLEDGE only to interpret the evidence.
3. Never change or invent trace measurements.
4. Separate confirmed trace facts from possible interpretations.
5. Do not attribute the socket to a database, cache, client, or service unless
   the trace identifies it.
6. State what additional evidence would confirm the application-level cause.
7. Recommend the next Trace Compass analysis when useful.
8. Cite relevant retrieved sources in the answer.
9. End the answer with a section titled exactly "All sources used:".
10. In that final section, list every retrieved source you used as numbered
    lines in the format "1) <title> - <source_url>".
"""
