from rag.config import DEFAULT_CONFIG, RAGConfig
from rag.index_builder import KnowledgeIndex
from rag.schemas import RetrievedDocument


class KnowledgeRetriever:
    QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

    def __init__(
        self,
        index: KnowledgeIndex | None = None,
        config: RAGConfig = DEFAULT_CONFIG,
    ):
        self.index = index or KnowledgeIndex(config)
        self.config = config

    def search(
        self,
        query: str,
        domain: str | None = None,
        limit: int | None = None,
    ) -> list[RetrievedDocument]:
        query_text = f"{self.QUERY_PREFIX}{query.strip()}"
        embedding = self.index.model.encode(
            query_text,
            normalize_embeddings=True,
        ).tolist()

        query_arguments = {
            "query_embeddings": [embedding],
            "n_results": limit or self.config.default_result_limit,
        }
        if domain is not None:
            query_arguments["where"] = {"domain": domain}

        results = self.index.collection.query(**query_arguments)
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        return [
            RetrievedDocument(
                text=document,
                metadata=metadata,
                distance=float(distance),
            )
            for document, metadata, distance in zip(
                documents,
                metadatas,
                distances,
            )
        ]

    @staticmethod
    def merge_by_distance(
        *document_lists: list[RetrievedDocument],
        limit: int,
    ) -> list[RetrievedDocument]:
        """Merge multiple ranked result lists into one, deduplicated by id.

        Used to combine a broad evidence-based search with a second,
        narrower search targeted at one specific signal (e.g. the
        extra_evidence_dispatch category) -- a single embedding for a long,
        multi-fact query can dilute a signal that only accounts for one
        sentence out of several, so a second, focused search plus a merge
        finds documents the combined query alone would miss.

        Confirmed empirically for critical_path.md: it ranked #1 in an
        isolated query for its own category fact, but did not appear in
        the top 8 results for the full combined evidence query (blocked
        time, dominant syscall, etc. dominated the embedding instead).
        """
        best_by_id: dict[str, RetrievedDocument] = {}

        for documents in document_lists:
            for document in documents:
                doc_id = document.metadata.get("id") or document.text
                existing = best_by_id.get(doc_id)
                if existing is None or document.distance < existing.distance:
                    best_by_id[doc_id] = document

        merged = sorted(
            best_by_id.values(),
            key=lambda document: document.distance,
        )
        return merged[:limit]
