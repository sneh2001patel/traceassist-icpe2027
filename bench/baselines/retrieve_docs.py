#!/usr/bin/env python3
"""Retrieval step of the LLM + RAG baseline on the symptom bench, adapted from CASCON
(../cascon_original/RAG_baseline/retrieve_docs.py): for each of the 112 bench question wordings,
fetch the documents TMLL's RAG layer (tmll/rag) retrieves, and freeze them in
retrieved_docs.json so every API call sees exactly the same documents.

Knowledge base: only TMLL's own documents, tmll/rag/knowledge, the same documents TraceAssist's
RAG step draws on. Unlike CASCON there is no program description: the user chose not to give the
baseline information about the bench programs that TraceAssist does not get (and the CASCON
batch_server description was moved out of tmll/rag/knowledge on 2026-11-22). The documents are
indexed into this folder's own Chroma store, rag_storage/, so TraceAssist's index is not touched.

As in CASCON (and the framework's build_thread_rag_response, minus TMLL): the search query is the
question text alone, without the verdict line or any trace evidence; the 6 nearest documents are
kept, and the top 3 get their full source page fetched live (rag/source_fetcher.attach_source_text).

Run with the TMLL environment, which has chromadb and sentence-transformers:
    "../../tmll/.venv/bin/python" retrieve_docs.py
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
TMLL_ROOT = BENCH.parent / "tmll"
KNOWLEDGE = TMLL_ROOT / "rag" / "knowledge"
STORAGE = HERE / "rag_storage"
OUT_FILE = HERE / "retrieved_docs.json"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--limit", type=int, default=6, help="documents per question (default 6)")
    p.add_argument("--no-fetch", action="store_true", help="use only the indexed text")
    p.add_argument("--force", action="store_true", help="rewrite an existing retrieved_docs.json")
    args = p.parse_args()
    if OUT_FILE.exists() and not args.force:
        sys.exit(f"{OUT_FILE.name} exists (frozen documents); pass --force to retrieve again")

    sys.path.insert(0, str(TMLL_ROOT))
    from rag.config import RAGConfig
    from rag.index_builder import KnowledgeIndex
    from rag.retriever import KnowledgeRetriever
    from rag.source_fetcher import attach_source_text

    config = RAGConfig(knowledge_directory=KNOWLEDGE, storage_directory=STORAGE)
    index = KnowledgeIndex(config)
    count = index.build(KNOWLEDGE, reset=True)
    print(f"indexed {count} files ({index.collection.count()} documents) from {KNOWLEDGE} into {STORAGE}")
    domains = sorted({m.get("domain") for m in index.collection.get(include=["metadatas"])["metadatas"]})
    print(f"domains: {domains}")
    if "workload" in domains:
        sys.exit("the knowledge base has workload (program description) documents; remove them first")

    retriever = KnowledgeRetriever(index=index, config=config)
    questions = json.loads((BENCH / "questions.json").read_text())["questions"]
    out = {}
    for q in questions:
        documents = retriever.search(q["text"], limit=args.limit)
        if not args.no_fetch:
            documents = attach_source_text(documents)
        out[q["id"]] = {
            "question": q["text"], "query": q["text"],
            "documents": [
                {"rank": rank, "id": d.metadata.get("id"), "title": d.metadata.get("title"),
                 "domain": d.metadata.get("domain"), "source_url": d.metadata.get("source_url"),
                 "distance": round(d.distance, 4), "text": d.text,
                 "full_source_text": d.full_source_text}
                for rank, d in enumerate(documents, 1)],
        }
        ids = ", ".join(f"{d.metadata.get('id')}{'*' if d.full_source_text else ''}" for d in documents)
        print(f"{q['id']:<5} {ids}", flush=True)
    OUT_FILE.write_text(json.dumps(out, indent=1) + "\n")
    print(f"{len(out)} questions -> {OUT_FILE}  (* = full source page fetched)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
