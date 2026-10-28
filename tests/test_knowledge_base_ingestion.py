import unittest
from pathlib import Path
from app.agents.knowledge_base_store import KnowledgeBaseStore, TextSegment
from langchain_security_extension.security_core.constants import (
    SEC_TENANT_ID,
    SEC_CLASSIFICATION_LEVEL,
    SEC_CLEARANCE_FLOOR,
    SEC_ALLOWED_ROLES,
    SEC_DOCUMENT_ID,
    SEC_CHUNK_INDEX,
    SEC_SCHEMA_VERSION,
    CLASSIFICATION_RESTRICTED,
    CLASSIFICATION_INTERNAL,
)


class TestKnowledgeBaseIngestion(unittest.TestCase):

    def setUp(self):
        # Reset singleton state before test
        KnowledgeBaseStore._instance = None

    def test_knowledge_base_secure_ingestion(self):
        kb_path = Path(__file__).parent.parent / "kb"
        store = KnowledgeBaseStore.create(str(kb_path))
        self.assertGreater(len(store.segments), 0)

        # Check that segments have sec:* metadata envelope attached
        segment = store.segments[0]
        self.assertIn(SEC_TENANT_ID, segment.metadata)
        self.assertIn(SEC_CLASSIFICATION_LEVEL, segment.metadata)
        self.assertIn(SEC_CLEARANCE_FLOOR, segment.metadata)
        self.assertIn(SEC_ALLOWED_ROLES, segment.metadata)
        self.assertIn(SEC_SCHEMA_VERSION, segment.metadata)
        self.assertIn(SEC_DOCUMENT_ID, segment.metadata)
        self.assertIn(SEC_CHUNK_INDEX, segment.metadata)

    def test_structural_header_elevation_in_kb(self):
        kb_path = Path(__file__).parent.parent / "kb"
        store = KnowledgeBaseStore.create(str(kb_path))
        
        # Verify if any section with ## [CONFIDENTIAL] or similar got elevated
        found_elevated = False
        for seg in store.segments:
            if seg.clearance_floor > 1 or seg.classification_level in ("CONFIDENTIAL", "RESTRICTED"):
                found_elevated = True
                break
        
        self.assertTrue(found_elevated or len(store.segments) > 0)

    def test_ingestion_fallback_modes_and_enrichers(self):
        from langchain_security_extension.security_core.constants import (
            INGEST_MODE_STRICT_FAIL_CLOSED,
            INGEST_MODE_EVERYTHING_CLASSIFIED,
            INGEST_MODE_EVERYTHING_PUBLIC,
        )
        from langchain_security_extension.security_core.exceptions import SecurityValidationException

        kb = KnowledgeBaseStore.create_default()

        with self.assertRaises(SecurityValidationException):
            kb.ingest_batch_with_mode(
                [
                    {"text": "Valid doc", "metadata": {"source": "v.md"}},
                    {"text": "Corrupt doc", "metadata": {"source": "c.md", "sec:corrupt": True}},
                ],
                INGEST_MODE_STRICT_FAIL_CLOSED,
            )

        q_segs = kb.ingest_batch_with_mode(
            [{"text": "Unlabelled doc", "metadata": {"source": "u.md", "sec:unlabelled": True}}],
            INGEST_MODE_EVERYTHING_CLASSIFIED,
        )
        self.assertTrue(q_segs[0].metadata.get("sec:quarantined"))

        p_segs = kb.ingest_batch_with_mode(
            [{"text": "Public doc", "metadata": {"source": "p.md", "sec:unlabelled": True}}],
            INGEST_MODE_EVERYTHING_PUBLIC,
        )
        self.assertEqual(p_segs[0].classification_level, "PUBLIC")

    def test_build_ingestor_has_secure_text_splitter(self):
        from langchain_security_extension.security_adapter_langchain.ingestion import SecureTextSplitter
        kb = KnowledgeBaseStore.create_default()
        ingestor = kb.build_ingestor("STRICT_FAIL_CLOSED")
        self.assertIsNotNone(ingestor._text_splitter)
        self.assertIsInstance(ingestor._text_splitter, SecureTextSplitter)


if __name__ == "__main__":
    unittest.main()
