import os
import math
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import chromadb
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

from app.config import config

KB_DIRECTORY_DEFAULT = Path(__file__).parent.parent.parent / "kb"
TOP_K_DEFAULT = 3
DEFAULT_EMBEDDING_DIMENSION = 128
DEFAULT_CHROMA_COLLECTION = config.chroma_collection
EMPTY_RUNBOOK_RESPONSE = "No specific runbook procedure found in knowledge base."
CHUNKING_DELIMITER = "\n\n"

logger = logging.getLogger("agent.knowledge_base")


class DeterministicEmbeddingFunction(EmbeddingFunction[Documents]):
    """Offline-safe, deterministic embedding function computing normalized token hash projections."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        dimension = args[0] if len(args) > 0 else kwargs.get("dimension", DEFAULT_EMBEDDING_DIMENSION)
        self.dimension = int(dimension)

    def name(self) -> str:
        return "deterministic_hash"

    def __call__(self, input: Documents) -> Embeddings:
        embeddings: List[List[float]] = []
        for text in input:
            vec = [0.0] * self.dimension
            for token in text.lower().split():
                h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
                idx = h % self.dimension
                sign = 1.0 if (h // self.dimension) % 2 == 0 else -1.0
                vec[idx] += sign
            norm = math.sqrt(sum(x * x for x in vec))
            if norm > 0.0:
                vec = [x / norm for x in vec]
            embeddings.append(vec)
        return embeddings


class TextSegment:
    """Represents a text segment with attached metadata attributes."""

    def __init__(self, text: str, source: str, *args: Any, **kwargs: Any) -> None:
        metadata: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("metadata")
        self.text = text
        self.source = source
        self.metadata = dict(metadata) if metadata is not None else {}

    @classmethod
    def create(cls, text: str, source: str, *args: Any, **kwargs: Any) -> "TextSegment":
        metadata: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("metadata")
        return cls(text, source, metadata=metadata)


class KnowledgeBaseStore:
    """Runbook document store providing retrieval for remediation guidance backed by ChromaDB in-memory."""

    _instance = None

    def __new__(cls, *args: Any, **kwargs: Any) -> "KnowledgeBaseStore":
        if cls._instance is None:
            cls._instance = super(KnowledgeBaseStore, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if self.initialized:
            return

        kb_path: Optional[str] = args[0] if len(args) > 0 else kwargs.get("kb_path")
        if kb_path is None:
            kb_path = str(KB_DIRECTORY_DEFAULT)

        self.kb_path = Path(kb_path)
        self.segments: List[TextSegment] = []

        self._client = chromadb.EphemeralClient()
        self._embedding_function = DeterministicEmbeddingFunction()
        self._collection = self._client.get_or_create_collection(
            name=DEFAULT_CHROMA_COLLECTION,
            embedding_function=self._embedding_function,
        )

        self._init_store()
        self.initialized = True

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "KnowledgeBaseStore":
        kb_path: Optional[str] = args[0] if len(args) > 0 else kwargs.get("kb_path")
        return cls(kb_path=kb_path)

    @classmethod
    def create_default(cls) -> "KnowledgeBaseStore":
        return cls()

    def _init_store(self) -> None:
        logger.info(f"Loading IT Runbooks into ChromaDB In-Memory Store from: {self.kb_path.absolute()}")
        if not self.kb_path.exists():
            logger.warning(f"KB directory {self.kb_path} does not exist. Initializing empty store.")
            return

        doc_count = 0
        ids_to_add: List[str] = []
        docs_to_add: List[str] = []
        metas_to_add: List[Dict[str, Any]] = []

        for doc_file in self.kb_path.glob("*.md"):
            try:
                content = doc_file.read_text(encoding="utf-8")
                chunks = [chunk.strip() for chunk in content.split(CHUNKING_DELIMITER) if chunk.strip()]
                for idx, chunk in enumerate(chunks):
                    doc_id = f"{doc_file.stem}_{idx}"
                    meta = {"source": doc_file.name, "chunk_index": idx}
                    ids_to_add.append(doc_id)
                    docs_to_add.append(chunk)
                    metas_to_add.append(meta)

                    segment = TextSegment.create(chunk, doc_file.name, metadata=meta)
                    self.segments.append(segment)
                doc_count += 1
            except Exception as exc:
                logger.error(f"Error loading runbook {doc_file}: {exc}")

        if ids_to_add:
            self._collection.add(
                ids=ids_to_add,
                documents=docs_to_add,
                metadatas=metas_to_add,
            )

        logger.info(f"Loaded {doc_count} runbook document(s) with {len(self.segments)} total segments into ChromaDB.")

    def search(
        self,
        query: str,
        *args: Any,
        **kwargs: Any,
    ) -> List[TextSegment]:
        """Search runbooks using ChromaDB vector similarity search."""
        if not query or self._collection.count() == 0:
            return []

        top_k: int = int(args[0]) if len(args) > 0 else int(kwargs.get("top_k", TOP_K_DEFAULT))
        actual_k = min(top_k, self._collection.count())
        if actual_k <= 0:
            return []

        query_results = self._collection.query(
            query_texts=[query],
            n_results=actual_k,
        )

        matched_segments: List[TextSegment] = []
        docs = query_results.get("documents", [[]])[0]
        metas = query_results.get("metadatas", [[]])[0]

        for doc_text, meta in zip(docs, metas):
            source = str(meta.get("source", "runbook")) if meta else "runbook"
            matched_segments.append(TextSegment.create(doc_text, source, metadata=meta))

        return matched_segments

    def search_as_string(
        self,
        query: str,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        results = self.search(
            query,
            *args,
            **kwargs,
        )
        if not results:
            return EMPTY_RUNBOOK_RESPONSE
        return "\n---\n".join([f"[{res.source}] {res.text}" for res in results])


kb_store_instance = KnowledgeBaseStore()
