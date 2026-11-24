from pathlib import Path
from typing import Any

import chromadb
import yaml
from sentence_transformers import SentenceTransformer

from rag.config import DEFAULT_CONFIG, RAGConfig


class KnowledgeIndex:
    def __init__(self, config: RAGConfig = DEFAULT_CONFIG):
        self.config = config
        self.model = SentenceTransformer(config.embedding_model)
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

    @staticmethod
    def _read_markdown(path: Path) -> tuple[dict[str, Any], str]:
        contents = path.read_text(encoding="utf-8")
        if not contents.startswith("---"):
            raise ValueError(f"Missing YAML front matter: {path}")

        parts = contents.split("---", maxsplit=2)
        if len(parts) != 3:
            raise ValueError(f"Invalid YAML front matter: {path}")

        metadata = yaml.safe_load(parts[1])
        if not isinstance(metadata, dict):
            raise ValueError(f"Invalid YAML front matter: {path}")

        text = parts[2].strip()
        required = {"id", "title", "domain", "source_url", "source_title"}
        missing = required.difference(metadata)
        if missing:
            raise ValueError(f"Missing {sorted(missing)} in {path}")

        return metadata, text

    def add_markdown(self, path: Path) -> None:
        metadata, text = self._read_markdown(path)
        document = (
            f"Title: {metadata['title']}\n"
            f"Domain: {metadata['domain']}\n\n"
            f"{text}"
        )
        embedding = self.model.encode(
            document,
            normalize_embeddings=True,
        ).tolist()

        self.collection.upsert(
            ids=[str(metadata["id"])],
            documents=[document],
            metadatas=[metadata],
            embeddings=[embedding],
        )

    def build(
        self,
        knowledge_directory: Path | None = None,
        reset: bool = True,
    ) -> int:
        directory = knowledge_directory or self.config.knowledge_directory
        paths = sorted(directory.rglob("*.md"))
        if not paths:
            raise ValueError(f"No Markdown documents found in {directory}")

        if reset:
            self._reset_collection()

        for path in paths:
            self.add_markdown(path)

        return len(paths)


if __name__ == "__main__":
    count = KnowledgeIndex().build()
    print(f"Indexed {count} knowledge documents")
