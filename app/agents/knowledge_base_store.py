import os
import math
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import chromadb
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings
from langchain_core.documents import Document
from langchain_core.vectorstores import VectorStore

from app.config import config

KB_DIRECTORY_DEFAULT = Path(__file__).parent.parent.parent / "kb"
TOP_K_DEFAULT = 3
DEFAULT_EMBEDDING_DIMENSION = 128
DEFAULT_CHROMA_COLLECTION = config.chroma_collection
EMPTY_RUNBOOK_RESPONSE = "No specific runbook procedure found in knowledge base."
CHUNKING_DELIMITER = "\n\n"

logger = logging.getLogger("agent.knowledge_base")


def to_chroma_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes metadata values into ChromaDB-compatible primitive scalar types."""
    chroma_meta: Dict[str, Any] = {}
    for k, v in meta.items():
        if isinstance(v, (str, int, float, bool)):
            chroma_meta[k] = v
        elif isinstance(v, (list, tuple, set)):
            chroma_meta[k] = ",".join(str(item) for item in v)
        elif v is None:
            chroma_meta[k] = ""
        else:
            chroma_meta[k] = str(v)
    return chroma_meta


class DeterministicEmbeddingFunction(EmbeddingFunction[Documents]):
    """Offline-safe, deterministic embedding function computing normalized token hash projections."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        dimension = args[0] if len(args) > 0 else kwargs.get("dimension", DEFAULT_EMBEDDING_DIMENSION)
        self.dimension = int(dimension)

    def name(self) -> str:
        return "deterministic_hash"

    def get_config(self) -> Dict[str, Any]:
        return {"dimension": self.dimension}

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

    @property
    def tenant_id(self) -> str:
        return str(self.metadata.get("sec:tenant_id", getattr(config, "default_tenant_id", "CORP_MAIN")))

    @property
    def classification_level(self) -> str:
        return str(self.metadata.get("sec:classification_level", "INTERNAL"))

    @property
    def clearance_floor(self) -> int:
        try:
            return int(self.metadata.get("sec:clearance_floor", 0))
        except (ValueError, TypeError):
            return 0

    @property
    def allowed_roles(self) -> List[str]:
        roles = self.metadata.get("sec:allowed_roles")
        if isinstance(roles, list):
            return roles
        if isinstance(roles, str) and roles:
            return [r.strip() for r in roles.split(",") if r.strip()]
        return []

    def to_context_string(self) -> str:
        """Formats segment text and metadata for context prompt injection."""
        return f"[{self.source}] {self.text}"


class ChromaVectorStore(VectorStore):
    """VectorStore adapter wrapping in-memory ChromaDB collection for BaseRetriever compatibility."""

    def __init__(self, collection: Any) -> None:
        self._collection = collection

    @property
    def embeddings(self) -> Optional[Any]:
        return None

    def add_texts(self, texts: Any, metadatas: Optional[Any] = None, **kwargs: Any) -> List[str]:
        return []

    @classmethod
    def from_texts(cls, texts: Any, embedding: Any, metadatas: Optional[Any] = None, **kwargs: Any) -> "ChromaVectorStore":
        raise NotImplementedError("from_texts not implemented for in-memory ChromaVectorStore")

    def similarity_search(self, query: str, k: int = TOP_K_DEFAULT, **kwargs: Any) -> List[Document]:
        filter_dict = kwargs.get("filter")
        query_kwargs: Dict[str, Any] = {"n_results": k}
        if filter_dict:
            query_kwargs["where"] = dict(filter_dict)
        res = self._collection.query(query_texts=[query], **query_kwargs)
        docs: List[Document] = []
        docs_list = res.get("documents", [[]])[0]
        metas_list = res.get("metadatas", [[]])[0]
        ids_list = res.get("ids", [[]])[0]
        for d_id, doc_text, meta in zip(ids_list, docs_list, metas_list):
            clean_meta = dict(meta or {})
            for role_key in ("sec:allowed_roles", "sec:required_roles", "roles"):
                roles_val = clean_meta.get(role_key)
                if isinstance(roles_val, str) and roles_val:
                    clean_meta[role_key] = [r.strip() for r in roles_val.split(",") if r.strip()]
            docs.append(Document(page_content=doc_text, metadata=clean_meta, id=d_id))
        return docs

    def fetch_page(self, offset: int, limit: int) -> List[Document]:
        """Fetches candidate chunks via offset-based collection scan."""
        if self._collection.count() == 0 or offset >= self._collection.count():
            return []
        res = self._collection.get(offset=offset, limit=limit)
        docs = res.get("documents", []) or []
        metas = res.get("metadatas", []) or []
        ids = res.get("ids", []) or []
        candidates: List[Document] = []
        for d_id, text, meta in zip(ids, docs, metas):
            clean_meta = dict(meta or {})
            for role_key in ("sec:allowed_roles", "sec:required_roles", "roles"):
                roles_val = clean_meta.get(role_key)
                if isinstance(roles_val, str) and roles_val:
                    clean_meta[role_key] = [r.strip() for r in roles_val.split(",") if r.strip()]
            candidates.append(Document(page_content=str(text), metadata=clean_meta, id=d_id))
        return candidates


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
        self._vector_store = ChromaVectorStore(self._collection)
        self._retriever = self._vector_store.as_retriever(search_kwargs={"k": TOP_K_DEFAULT})

        self._init_store()
        self.initialized = True

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "KnowledgeBaseStore":
        kb_path: Optional[str] = args[0] if len(args) > 0 else kwargs.get("kb_path")
        return cls(kb_path=kb_path)

    @classmethod
    def create_default(cls) -> "KnowledgeBaseStore":
        return cls()

    def _add_segments_to_collection(self, segments_data: List[Dict[str, Any]]) -> None:
        """Helper to batch register text segments into ChromaDB and the local memory list."""
        ids_to_add: List[str] = []
        docs_to_add: List[str] = []
        metas_to_add: List[Dict[str, Any]] = []

        for item in segments_data:
            doc_id = str(item["id"])
            text = str(item["text"])
            source = str(item["source"])
            meta = dict(item.get("metadata", {}))

            ids_to_add.append(doc_id)
            docs_to_add.append(text)
            metas_to_add.append(to_chroma_metadata(meta))

            segment = TextSegment.create(text, source, metadata=meta)
            self.segments.append(segment)

        if ids_to_add:
            self._collection.add(
                ids=ids_to_add,
                documents=docs_to_add,
                metadatas=metas_to_add,
            )

    def _init_store(self) -> None:
        """Loads and indexes runbook documents from the configured knowledge base directory."""
        logger.info(f"Loading IT Runbooks into ChromaDB In-Memory Store from: {self.kb_path.absolute()}")
        if not self.kb_path.exists():
            logger.warning(f"KB directory {self.kb_path} does not exist. Initializing empty store.")
            return

        doc_count = 0
        items_to_add: List[Dict[str, Any]] = []

        for doc_file in self.kb_path.glob("*.md"):
            try:
                content = doc_file.read_text(encoding="utf-8")
                chunks = [chunk.strip() for chunk in content.split(CHUNKING_DELIMITER) if chunk.strip()]
                for idx, chunk in enumerate(chunks):
                    doc_id = f"{doc_file.stem}_{idx}"
                    meta = {"source": doc_file.name, "chunk_index": idx}
                    items_to_add.append({
                        "id": doc_id,
                        "text": chunk,
                        "source": doc_file.name,
                        "metadata": meta,
                    })
                doc_count += 1
            except Exception as exc:
                logger.error(f"Error loading runbook {doc_file}: {exc}")

        if items_to_add:
            self._add_segments_to_collection(items_to_add)

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

        docs = self._retriever.invoke(query, top_k=actual_k)

        matched_segments: List[TextSegment] = []
        for doc in docs:
            source = str(getattr(doc, "metadata", {}).get("source", "runbook"))
            content = doc.page_content if hasattr(doc, "page_content") else str(doc)
            matched_segments.append(TextSegment.create(content, source, metadata=getattr(doc, "metadata", {})))

        return matched_segments

    def search_as_string(
        self,
        query: str,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Searches runbooks and returns concatenated markdown strings for prompt context injection."""
        results = self.search(
            query,
            *args,
            **kwargs,
        )
        if not results:
            return EMPTY_RUNBOOK_RESPONSE
        return "\n---\n".join([res.to_context_string() for res in results])


kb_store_instance = KnowledgeBaseStore()
