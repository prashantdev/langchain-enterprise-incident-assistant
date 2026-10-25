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

from security_adapter_langchain.ingestion import (
    DocumentSecurityTransformer,
    SecureDocumentChunkEnricher,
    SecurityEnvelopeValidator,
    SecureVectorStoreIngestor,
    SecureTextSplitter,
    HeadingClassificationEnricher,
    DlpSecretDetectionEnricher,
    LangChainDocumentLike,
)
from security_adapter_langchain.retriever_wrapper import SecureRetriever, SecureDocument
from security_core.identity import SecurityIdentity
from security_core.constants import (
    SEC_TENANT_ID,
    SEC_CLASSIFICATION_LEVEL,
    SEC_CLEARANCE_FLOOR,
    SEC_ALLOWED_ROLES,
    CLASSIFICATION_INTERNAL,
    CLASSIFICATION_RESTRICTED,
    STORE_PROFILE_FULL_AST,
)
from app.config import config
from app.security.security_integration import get_pdp_engine
from app.security.master_data import (
    ROLE_USER,
    ROLE_DEVOPS_ENGINEER,
    ROLE_ADMIN,
)

KB_DIRECTORY_DEFAULT = Path(__file__).parent.parent.parent / "kb"
TOP_K_DEFAULT = 3
DEFAULT_EMBEDDING_DIMENSION = 128
DEFAULT_CHROMA_COLLECTION = config.chroma_collection
EMPTY_RUNBOOK_RESPONSE = "No specific runbook procedure found in knowledge base."
CHUNKING_DELIMITER = "\n\n"
DEFAULT_CHUNK_SIZE = 1000
DEFAULT_CHUNK_OVERLAP = 200
DEFAULT_TENANT_PARAM = config.default_tenant_id
DEFAULT_DEPARTMENT_PARAM = config.default_department_id
DEFAULT_CLASSIFICATION_PARAM = CLASSIFICATION_INTERNAL
DEFAULT_ROLES_PARAM: List[str] = [ROLE_USER, ROLE_DEVOPS_ENGINEER, ROLE_ADMIN]
DEFAULT_OVERSAMPLING_FACTOR = config.default_oversampling_factor

logger = logging.getLogger("agent.knowledge_base")


def kb_security_rule(content: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Infers restricted classification and admin-only access for sensitive runbooks."""
    source = str(meta.get("source", "")).lower()
    if "201" in source or "admin-credentials" in source or "top_secret" in content.lower() or "restricted" in content.lower():
        return {
            "classification": CLASSIFICATION_RESTRICTED,
            "clearance": 3,
            "roles": [ROLE_ADMIN],
        }
    return {}


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
        return str(self.metadata.get(SEC_TENANT_ID, DEFAULT_TENANT_PARAM))

    @property
    def classification_level(self) -> str:
        return str(self.metadata.get(SEC_CLASSIFICATION_LEVEL, DEFAULT_CLASSIFICATION_PARAM))

    @property
    def clearance_floor(self) -> int:
        try:
            return int(self.metadata.get(SEC_CLEARANCE_FLOOR, 0))
        except (ValueError, TypeError):
            return 0

    @property
    def allowed_roles(self) -> List[str]:
        roles = self.metadata.get(SEC_ALLOWED_ROLES)
        if isinstance(roles, list):
            return roles
        if isinstance(roles, str) and roles:
            return [r.strip() for r in roles.split(",") if r.strip()]
        return list(DEFAULT_ROLES_PARAM)

    def to_context_string(self) -> str:
        """Formats segment text and metadata for context prompt injection."""
        meta = self.metadata
        if any(k.startswith("sec:") for k in meta.keys()):
            env_str = (
                f"[sec:tenantId={self.tenant_id}, sec:clearanceFloor={self.clearance_floor}, "
                f"sec:allowedRoles={self.allowed_roles}, sec:envelope_hash={meta.get('sec:envelope_hash', 'N/A')}]"
            )
            return f"[{self.source}] {env_str} {self.text}"
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

        pdp_engine = get_pdp_engine()
        base_retriever = self._vector_store.as_retriever(search_kwargs={"k": TOP_K_DEFAULT})
        self._retriever = SecureRetriever.wrap(
            base_retriever,
            pdp_engine=pdp_engine,
            oversampling_factor=DEFAULT_OVERSAMPLING_FACTOR,
            secret_key=config.security_hmac_secret,
            store_profile=STORE_PROFILE_FULL_AST,
            secondary_fetch_fn=self._secondary_fetch_chroma_page,
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

    def build_ingestor(self, ingestion_mode: str) -> SecureVectorStoreIngestor:
        """Constructs an instantiated SecureVectorStoreIngestor for the requested mode."""
        pdp_engine = get_pdp_engine()
        audit_mgr = getattr(pdp_engine, "audit_manager", None)
        transformer = DocumentSecurityTransformer.create(
            default_classification=DEFAULT_CLASSIFICATION_PARAM,
            default_roles=DEFAULT_ROLES_PARAM,
            default_tenant=DEFAULT_TENANT_PARAM,
            default_department=DEFAULT_DEPARTMENT_PARAM,
            rules=[kb_security_rule],
        )
        spi_enrichers = [
            HeadingClassificationEnricher.create(),
            DlpSecretDetectionEnricher.create(),
        ]
        enricher = SecureDocumentChunkEnricher.create(
            spi_enrichers=spi_enrichers,
            secret_key=config.security_hmac_secret,
            audit_manager=audit_mgr,
        )
        validator = SecurityEnvelopeValidator.create(secret_key=config.security_hmac_secret)
        text_splitter = SecureTextSplitter.create(
            chunk_size=DEFAULT_CHUNK_SIZE,
            chunk_overlap=DEFAULT_CHUNK_OVERLAP,
        )
        return SecureVectorStoreIngestor.create(
            transformer=transformer,
            enricher=enricher,
            validator=validator,
            ingestion_mode=ingestion_mode,
            text_splitter=text_splitter,
            audit_manager=audit_mgr,
        )

    def _add_segments_to_collection(self, segments_data: List[Dict[str, Any]]) -> List[TextSegment]:
        """Helper to batch register text segments into ChromaDB and the local memory list."""
        ids_to_add: List[str] = []
        docs_to_add: List[str] = []
        metas_to_add: List[Dict[str, Any]] = []
        created_segments: List[TextSegment] = []

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
            created_segments.append(segment)

        if ids_to_add:
            self._collection.add(
                ids=ids_to_add,
                documents=docs_to_add,
                metadatas=metas_to_add,
            )

        return created_segments

    def _init_store(self) -> None:
        """Loads and indexes runbook documents from the configured knowledge base directory."""
        logger.info(f"Loading IT Runbooks into ChromaDB In-Memory Store from: {self.kb_path.absolute()}")
        if not self.kb_path.exists():
            logger.warning(f"KB directory {self.kb_path} does not exist. Initializing empty store.")
            return

        ingestor = self.build_ingestor(config.ingestion_mode)
        doc_count = 0
        items_to_add: List[Dict[str, Any]] = []

        for doc_file in self.kb_path.glob("*.md"):
            try:
                content = doc_file.read_text(encoding="utf-8")
                secure_docs = ingestor.ingest_text(
                    text=content,
                    source_name=doc_file.name,
                    metadata={"source": doc_file.name},
                )
                for idx, doc in enumerate(secure_docs):
                    doc_id = f"{doc_file.stem}_{idx}"
                    items_to_add.append({
                        "id": doc_id,
                        "text": doc.page_content,
                        "source": doc_file.name,
                        "metadata": doc.metadata,
                    })
                doc_count += 1
            except Exception as exc:
                logger.error(f"Error loading runbook {doc_file}: {exc}")

        if items_to_add:
            self._add_segments_to_collection(items_to_add)

        logger.info(f"Loaded {doc_count} runbook document(s) with {len(self.segments)} total segments into ChromaDB.")

    def ingest_batch_with_mode(
        self,
        raw_documents: List[Dict[str, Any]],
        ingestion_mode: str,
    ) -> List[TextSegment]:
        """Ingests a dynamic batch of documents using the specified security ingestion policy mode."""
        ingestor = self.build_ingestor(ingestion_mode)
        docs = [
            LangChainDocumentLike.create(
                page_content=str(d.get("text", "")),
                metadata=dict(d.get("metadata", {})),
            )
            for d in raw_documents
        ]
        ingested = ingestor.ingest_documents(docs)
        items_to_add: List[Dict[str, Any]] = []

        for idx, doc in enumerate(ingested):
            source = str(doc.metadata.get("source", "batch_doc"))
            doc_id = f"batch_{source}_{idx}_{len(self.segments)}"
            items_to_add.append({
                "id": doc_id,
                "text": doc.page_content,
                "source": source,
                "metadata": doc.metadata,
            })

        return self._add_segments_to_collection(items_to_add)

    def _secondary_fetch_chroma_page(self, offset: int, limit: int) -> List[SecureDocument]:
        """Secondary paging callback for ChromaDB vector store when result starvation occurs."""
        docs = self._vector_store.fetch_page(offset=offset, limit=limit)
        return [SecureDocument.create(page_content=d.page_content, metadata=d.metadata) for d in docs]

    def search(
        self,
        query: str,
        *args: Any,
        **kwargs: Any,
    ) -> List[TextSegment]:
        """Search runbooks using ChromaDB vector similarity search with AST push-down and PEP post-pruning."""
        if not query or self._collection.count() == 0:
            return []

        top_k: int = int(args[0]) if len(args) > 0 else int(kwargs.get("top_k", TOP_K_DEFAULT))
        run_config: Optional[Dict[str, Any]] = args[1] if len(args) > 1 else kwargs.get("config")
        identity = kwargs.get("identity")
        if run_config is None:
            from security_core.identity import IdentityBridge
            resolved_identity = IdentityBridge.resolve_identity(identity)
            run_config = IdentityBridge.create_runnable_config(resolved_identity)
        elif identity is not None and isinstance(run_config, dict):
            run_config.setdefault("configurable", {})["security_identity"] = identity

        pruned_docs = self._retriever.invoke(
            query,
            config=run_config,
            top_k=top_k,
        )

        matched_segments: List[TextSegment] = []
        for doc in pruned_docs:
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
