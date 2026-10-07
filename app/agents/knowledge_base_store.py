import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

KB_DIRECTORY_DEFAULT = "kb"
TOP_K_DEFAULT = 3
logger = logging.getLogger("agent.knowledge_base")


class TextSegment:
    """Represents a text segment with attached metadata attributes."""

    def __init__(self, text: str, source: str, metadata: Optional[Dict[str, Any]] = None):
        self.text = text
        self.source = source
        self.metadata = dict(metadata) if metadata is not None else {}

    @classmethod
    def create(cls, text: str, source: str, metadata: Optional[Dict[str, Any]] = None) -> "TextSegment":
        return cls(text=text, source=source, metadata=metadata)


class KnowledgeBaseStore:
    """Runbook document store providing retrieval for remediation guidance."""

    _instance = None

    def __new__(cls, kb_path: str = None):
        if cls._instance is None:
            cls._instance = super(KnowledgeBaseStore, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self, kb_path: str = None):
        if self.initialized:
            return

        if kb_path is None:
            kb_path = KB_DIRECTORY_DEFAULT

        self.kb_path = Path(kb_path)
        self.segments: List[TextSegment] = []
        self._init_store()
        self.initialized = True

    @classmethod
    def create(cls, kb_path: Optional[str] = None) -> "KnowledgeBaseStore":
        return cls(kb_path=kb_path)

    @classmethod
    def create_default(cls) -> "KnowledgeBaseStore":
        return cls()

    def _init_store(self) -> None:
        logger.info(f"Loading IT Runbooks into In-Memory Store from: {self.kb_path.absolute()}")
        if not self.kb_path.exists():
            logger.warning(f"KB directory {self.kb_path} does not exist. Initializing empty store.")
            return

        doc_count = 0
        for doc_file in self.kb_path.glob("*.md"):
            try:
                content = doc_file.read_text(encoding="utf-8")
                # Simple chunking by paragraphs / sections
                chunks = [chunk.strip() for chunk in content.split("\n\n") if chunk.strip()]
                for chunk in chunks:
                    self.segments.append(TextSegment(text=chunk, source=doc_file.name))
                doc_count += 1
            except Exception as exc:
                logger.error(f"Error loading runbook {doc_file}: {exc}")

        logger.info(f"Loaded {doc_count} runbook document(s) with {len(self.segments)} total segments.")

    def search(self, query: str, top_k: int = TOP_K_DEFAULT, config: Optional[Dict[str, Any]] = None) -> List[TextSegment]:
        """Search runbooks for query keywords matching relevant procedures."""
        if not query or not self.segments:
            return []

        query_words = set(query.lower().split())
        scored_segments = []

        for segment in self.segments:
            seg_text_lower = segment.text.lower()
            score = sum(1 for word in query_words if word in seg_text_lower)
            if score > 0:
                scored_segments.append((score, segment))

        scored_segments.sort(key=lambda x: x[0], reverse=True)
        return [seg for _, seg in scored_segments[:top_k]]

    def search_as_string(self, query: str, top_k: int = TOP_K_DEFAULT, config: Optional[Dict[str, Any]] = None) -> str:
        results = self.search(query, top_k=top_k, config=config)
        if not results:
            return "No specific runbook procedure found in knowledge base."
        return "\n---\n".join([f"[{res.source}] {res.text}" for res in results])


kb_store_instance = KnowledgeBaseStore()
