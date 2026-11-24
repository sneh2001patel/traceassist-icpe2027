from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RAGConfig:
    knowledge_directory: Path = Path("rag/knowledge")
    storage_directory: Path = Path("rag/storage")
    collection_name: str = "tmll_knowledge"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    default_result_limit: int = 6


DEFAULT_CONFIG = RAGConfig()
