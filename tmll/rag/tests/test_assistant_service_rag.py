from rag.schemas import RetrievedDocument
from tmll_assistant_service import build_thread_rag_response


class FakeRetriever:
    def search(self, query: str, domain: str | None = None, limit: int | None = None):
        assert "recvfrom" in query
        assert domain == "kernel_tracing"
        assert limit == 2
        return [
            RetrievedDocument(
                text="A blocking recvfrom waits for socket data.",
                metadata={
                    "title": "Blocking in recvfrom",
                    "domain": "kernel_tracing",
                    "source_url": "https://example.com/recvfrom",
                },
                distance=0.12,
            )
        ]


def test_build_thread_rag_response_prepares_prompt_without_llm_call():
    response = build_thread_rag_response(
        question="Why was thread 2327 slow?",
        analysis={
            "tid": 2327,
            "process_name": "python",
            "blocked_ms": 233.786,
            "waiting_for_cpu_ms": 3.536,
            "running_ms": 189.739,
            "dominant_blocking_syscall": "recvfrom",
            "longest_blocked_interval_ms": 30.878,
        },
        retriever=FakeRetriever(),
        domain="kernel_tracing",
        limit=2,
    )

    assert response["question"] == "Why was thread 2327 slow?"
    assert response["evidence"]["tid"] == 2327
    assert response["evidence"]["dominant_blocking_syscall"] == "recvfrom"
    assert response["retrieved_documents"][0]["metadata"]["title"] == (
        "Blocking in recvfrom"
    )
    assert "TRACE EVIDENCE" in response["prompt"]
    assert response["llm_answer"] is None
    assert "Trace Compass Java owns the LLM call" in response["note"]
