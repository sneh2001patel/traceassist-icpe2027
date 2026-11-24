from pathlib import Path

import chromadb
import numpy as np
import pytest

from rag.config import RAGConfig
from rag.evidence_builder import EvidenceBuilder
from rag.index_builder import KnowledgeIndex
from rag.prompt_builder import PromptBuilder
from rag.retriever import KnowledgeRetriever
from rag.schemas import RetrievedDocument


class FakeEmbeddingModel:
    def encode(self, document: str, normalize_embeddings: bool = True):
        text = document.lower()
        values = np.array(
            [
                text.count("recvfrom") + text.count("socket"),
                text.count("control flow") + text.count("thread states"),
                text.count("django"),
            ],
            dtype=float,
        )
        if normalize_embeddings and np.linalg.norm(values):
            values = values / np.linalg.norm(values)
        return values


class FakeKnowledgeIndex(KnowledgeIndex):
    def __init__(self, config: RAGConfig):
        self.config = config
        self.model = FakeEmbeddingModel()
        self.client = chromadb.PersistentClient(
            path=str(config.storage_directory)
        )
        self.collection = self.client.get_or_create_collection(
            name=config.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def _reset_collection(self) -> None:
        self.client.delete_collection(name=self.config.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.config.collection_name,
            metadata={"hnsw:space": "cosine"},
        )


def write_doc(
    directory: Path,
    filename: str = "recvfrom.md",
    *,
    doc_id: str = "kernel-recvfrom-001",
    title: str = "Blocking in recvfrom",
    domain: str = "kernel_tracing",
    text: str = "The recvfrom system call can block while waiting for socket data.",
) -> Path:
    path = directory / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""---
id: {doc_id}
title: {title}
domain: {domain}
source_url: https://example.com/{doc_id}
source_title: Example source
---

# {title}

{text}
""",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def rag_config(tmp_path):
    return RAGConfig(
        knowledge_directory=tmp_path / "knowledge",
        storage_directory=tmp_path / "storage",
        collection_name="test_knowledge",
        embedding_model="fake-model",
    )


def test_valid_markdown_file_is_indexed(rag_config):
    write_doc(rag_config.knowledge_directory)

    index = FakeKnowledgeIndex(rag_config)

    assert index.build() == 1
    assert index.collection.count() == 1


def test_markdown_without_front_matter_is_rejected(tmp_path):
    path = tmp_path / "invalid.md"
    path.write_text("# Missing metadata\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Missing YAML front matter"):
        KnowledgeIndex._read_markdown(path)


def test_markdown_missing_required_metadata_is_rejected(tmp_path):
    path = tmp_path / "invalid.md"
    path.write_text(
        """---
id: missing-domain
title: Missing Domain
source_url: https://example.com
source_title: Example
---

# Missing Domain
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Missing"):
        KnowledgeIndex._read_markdown(path)


def test_rebuilding_index_does_not_duplicate_ids(rag_config):
    write_doc(rag_config.knowledge_directory)
    index = FakeKnowledgeIndex(rag_config)

    index.build()
    index.build()

    assert index.collection.count() == 1


def test_rebuilding_index_removes_stale_documents(rag_config):
    stale_path = write_doc(
        rag_config.knowledge_directory,
        "stale.md",
        doc_id="stale-doc",
        title="Stale doc",
        text="This document should be removed from the index.",
    )
    write_doc(rag_config.knowledge_directory)
    index = FakeKnowledgeIndex(rag_config)
    index.build()

    stale_path.unlink()
    index.build()

    assert index.collection.count() == 1
    assert index.collection.get()["ids"] == ["kernel-recvfrom-001"]


def test_recvfrom_query_retrieves_recvfrom_document(rag_config):
    write_doc(rag_config.knowledge_directory)
    write_doc(
        rag_config.knowledge_directory,
        "control_flow.md",
        doc_id="trace-compass-control-flow-001",
        title="Control Flow view",
        domain="trace_compass",
        text="The Control Flow view shows thread states over time.",
    )
    index = FakeKnowledgeIndex(rag_config)
    index.build()

    results = KnowledgeRetriever(index=index, config=rag_config).search(
        "Why would a Python thread block in recvfrom?",
        limit=2,
    )

    assert results[0].metadata["id"] == "kernel-recvfrom-001"


def test_domain_filter_returns_only_trace_compass_documents(rag_config):
    write_doc(rag_config.knowledge_directory)
    write_doc(
        rag_config.knowledge_directory,
        "control_flow.md",
        doc_id="trace-compass-control-flow-001",
        title="Control Flow view",
        domain="trace_compass",
        text="The Control Flow view shows thread states over time.",
    )
    index = FakeKnowledgeIndex(rag_config)
    index.build()

    results = KnowledgeRetriever(index=index, config=rag_config).search(
        "Which view shows blocked thread states?",
        domain="trace_compass",
        limit=3,
    )

    assert results
    assert {result.metadata["domain"] for result in results} == {"trace_compass"}


def test_evidence_builder_preserves_and_derives_values():
    evidence = EvidenceBuilder.from_thread_analysis(
        {
            "tid": 2327,
            "process_name": "python",
            "blocked_ms": 233.786,
            "waiting_for_cpu_ms": 3.536,
            "running_ms": 189.739,
            "longest_blocked_intervals": [{"duration_ms": 30.878}],
            "syscall_latency_correlation": {
                "available": True,
                "correlations": [
                    {
                        "overlapping_syscalls": [
                            {
                                "system_call": "recvfrom",
                                "overlap_duration_ms": 20.0,
                            },
                            {
                                "system_call": "futex",
                                "overlap_duration_ms": 2.0,
                            },
                        ],
                    },
                    {
                        "overlapping_syscalls": [
                            {
                                "system_call": "recvfrom",
                                "overlap_duration_ms": 10.0,
                            }
                        ],
                    },
                ],
            },
        }
    )

    assert evidence.tid == 2327
    assert evidence.process_name == "python"
    assert evidence.blocked_ms == 233.786
    assert evidence.runnable_ms == 3.536
    assert evidence.running_ms == 189.739
    assert evidence.system_call_ms == 0.0
    assert evidence.longest_blocked_interval_ms == 30.878
    assert evidence.dominant_blocking_syscall == "recvfrom"


def test_prompt_includes_question_evidence_sources_and_instructions():
    evidence = EvidenceBuilder.from_thread_analysis(
        {
            "tid": 2327,
            "process_name": "python",
            "blocked_ms": 233.786,
            "runnable_ms": 3.536,
            "user_mode_ms": 165.298,
            "system_call_ms": 24.441,
            "dominant_blocking_syscall": "recvfrom",
            "longest_blocked_interval_ms": 30.878,
        }
    )
    documents = [
        RetrievedDocument(
            text="The recvfrom system call receives data from a socket.",
            metadata={
                "title": "Blocking in recvfrom",
                "source_url": "https://example.com/recvfrom",
            },
            distance=0.1,
        )
    ]

    prompt = PromptBuilder.build(
        "Why was thread 2327 slow?",
        evidence,
        documents,
    )

    assert "Why was thread 2327 slow?" in prompt
    assert "Thread: 2327 (python)" in prompt
    assert "Dominant blocking syscall: recvfrom" in prompt
    assert "https://example.com/recvfrom" in prompt
    assert "Treat TRACE EVIDENCE as authoritative" in prompt
    assert 'section titled exactly "All sources used:"' in prompt
    assert 'format "1) <title> - <source_url>"' in prompt


def test_bundled_knowledge_base_has_expected_documents():
    knowledge_dir = Path(__file__).resolve().parents[1] / "knowledge"
    paths = sorted(knowledge_dir.rglob("*.md"))
    domains = {}

    for path in paths:
        metadata, text = KnowledgeIndex._read_markdown(path)
        assert text
        domains[metadata["domain"]] = domains.get(metadata["domain"], 0) + 1

    assert len(paths) == 35
    assert domains == {
        "django": 10,
        "kernel_tracing": 15,
        "trace_compass": 10,
    }
