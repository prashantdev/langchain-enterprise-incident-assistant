import unittest
from pathlib import Path
from app.agents.knowledge_base_store import KnowledgeBaseStore
from security_core.identity import SecurityIdentity
from app.security.security_integration import get_audit_events, DEFAULT_AUDIT_LOG_FILE


class TestSecureRetrieverIntegration(unittest.TestCase):

    def setUp(self):
        KnowledgeBaseStore._instance = None
        kb_path = Path(__file__).parent.parent / "kb"
        self.store = KnowledgeBaseStore.create(str(kb_path))

    def test_low_clearance_user_cannot_access_classified_runbook_201(self):
        identity_level_1 = SecurityIdentity.create(
            subject_id="sarah.employee@enterprise.com",
            tenant_id="CORP_MAIN",
            roles={"ROLE_DEVOPS_ENGINEER"},
            clearance_level=1,
            department_id="HR",
            attributes={},
        )

        results = self.store.search(
            query="account escalation password reset Runbook 201",
            top_k=3,
            identity=identity_level_1,
        )

        # Runbook 201 (clearance floor 3) must be pruned for level 1 user
        for seg in results:
            self.assertNotIn("Runbook 201", seg.text)
            self.assertLessEqual(seg.clearance_floor, 1)

    def test_high_clearance_admin_can_access_classified_runbook_201(self):
        identity_admin = SecurityIdentity.create(
            subject_id="alex.devops@enterprise.com",
            tenant_id="CORP_MAIN",
            roles={"ROLE_ADMIN"},
            clearance_level=3,
            department_id="IT_OPS",
            attributes={},
        )

        results = self.store.search(
            query="account escalation password reset Runbook 201",
            top_k=3,
            identity=identity_admin,
        )

        # High clearance admin caller should retrieve matching runbooks including 201
        found_201 = any("201" in seg.source or "Runbook 201" in seg.text for seg in results)
        self.assertTrue(found_201)

    def test_foreign_tenant_isolation(self):
        identity_foreign = SecurityIdentity.create(
            subject_id="external.user@foreign.com",
            tenant_id="CORP_FOREIGN",
            roles={"ROLE_USER"},
            clearance_level=1,
            department_id="EXTERNAL",
            attributes={},
        )

        results = self.store.search(
            query="web app diagnostics database reset",
            top_k=3,
            identity=identity_foreign,
        )

        # Cross-tenant search must return 0 results
        self.assertEqual(len(results), 0)

    def test_hmac_tamper_detection_prunes_chunk(self):
        from app.agents.knowledge_base_store import TextSegment
        from app.security.user_registry import UserRegistry
        from app.security.security_integration import get_pdp_engine, security_identity_from_context
        from security_core.identity import IdentityBridge
        from security_core.constants import SEC_CLEARANCE_FLOOR, EVENT_POLICY_TAMPER_DETECTED

        registry = UserRegistry()
        sec_ctx = registry.build_security_context("alex.devops@enterprise.com")
        sec_id = security_identity_from_context(sec_ctx)
        cfg = IdentityBridge.create_runnable_config(sec_id)

        base_seg = self.store.segments[0]
        tampered_meta = dict(base_seg.metadata)
        tampered_meta[SEC_CLEARANCE_FLOOR] = 99
        tampered_seg = TextSegment.create(base_seg.text, base_seg.source, metadata=tampered_meta)

        pruned = self.store._retriever.prune_candidates([tampered_seg], sec_id, top_k=1, config=cfg)
        self.assertEqual(len(pruned), 0)
        events = get_audit_events(DEFAULT_AUDIT_LOG_FILE)
        self.assertTrue(any(getattr(e, "reason_code", "") == EVENT_POLICY_TAMPER_DETECTED for e in events))

    def test_adaptive_secondary_paging_and_starvation_audit(self):
        from security_core.constants import EVENT_RAG_RESULT_STARVATION

        # Request more authorized items than exist for this caller to trigger secondary paging and starvation
        identity_admin = SecurityIdentity.create(
            subject_id="alex.devops@enterprise.com",
            tenant_id="CORP_MAIN",
            roles={"ROLE_ADMIN"},
            clearance_level=3,
            department_id="IT_OPS",
            attributes={},
        )

        results = self.store.search(
            query="database reset",
            top_k=25,
            identity=identity_admin,
        )

        events = get_audit_events(DEFAULT_AUDIT_LOG_FILE)
        starvation_events = [e for e in events if getattr(e, "reason_code", "") == EVENT_RAG_RESULT_STARVATION]
        self.assertGreaterEqual(len(starvation_events), 1)
        self.assertLess(len(results), 25)



if __name__ == "__main__":
    unittest.main()

