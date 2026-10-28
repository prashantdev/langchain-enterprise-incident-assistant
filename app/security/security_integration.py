import os
import json
from typing import Optional, Dict, Any, Set, List
from langchain_security_extension.security_core.identity import SecurityIdentity, SecurityContextHolder, IdentityBridge
from langchain_security_extension.security_core.pdp import (
    EmbeddedPolicyEngine,
    RoleGraph,
    PolicyDecisionEngine,
    TwoTierDecisionCache,
    PolicyRequest,
    PolicyDecision,
)
from langchain_security_extension.security_core.cel_evaluator import CELEvaluator
from langchain_security_extension.security_core.audit import (
    AuditManager,
    JsonFileAuditLogger,
    ElasticCommonSchemaPublisher,
    OpenTelemetryLogsPublisher,
    SplunkHecPublisher,
    AuditEvent,
    AuditSanitizer,
)
from langchain_security_extension.security_pdp_opa.opa_adapter import RemotePDPAdapter, OPACacheInvalidationHandler
from langchain_security_extension.security_adapter_langchain.runnable_guard import SecureRunnable
from langchain_security_extension.security_core.pii import set_pii_scope, reset_pii_scope, reset_pii_sanitizer
from app.config import config
from app.security.master_data import (
    ROLE_ADMIN,
    ROLE_DEVOPS_ENGINEER,
    ROLE_SUPPORT_AGENT,
    ROLE_USER,
    DEFAULT_TENANT_ID,
    ENTERPRISE_TENANT_ID,
)
from app.security.models import SecurityContext
from app.security.entity_resolver import entity_resolver_instance

CLEARANCE_RANK_MAP: Dict[str, int] = {
    "TOP_SECRET": 3,
    "SECRET": 2,
    "STANDARD": 1,
    "UNAUTHENTICATED": 0,
    ROLE_ADMIN: 3,
    ROLE_DEVOPS_ENGINEER: 2,
    ROLE_SUPPORT_AGENT: 2,
    ROLE_USER: 1,
}
DEFAULT_CLEARANCE_RANK = 1

ALLOWED_TENANTS: Set[str] = {
    DEFAULT_TENANT_ID,
    ENTERPRISE_TENANT_ID,
    "CORP_MAIN",
}

TRIAGE_REQUIRED_ROLES: List[str] = [
    ROLE_USER,
    ROLE_DEVOPS_ENGINEER,
    ROLE_SUPPORT_AGENT,
    ROLE_ADMIN,
]
TRIAGE_MIN_CLEARANCE = 1
DEFAULT_AUDIT_LOG_FILE = "logs/security-audit.json"


class JsonAuditEventRecord:
    """Read-only view of a serialized audit event from JSON log file."""

    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        return self._data.get(name)

    def __getitem__(self, item: str) -> Any:
        return self._data[item]

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._data.get(*args, **kwargs)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)


def get_audit_events(file_path: str) -> List[JsonAuditEventRecord]:
    """Flushes active AuditManager and returns parsed audit events from the target JSON log file."""
    pdp = get_pdp_engine()
    audit_mgr = getattr(pdp, "audit_manager", None)
    if audit_mgr:
        audit_mgr.flush()
    if not os.path.exists(file_path):
        return []
    records: List[JsonAuditEventRecord] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                try:
                    records.append(JsonAuditEventRecord(json.loads(stripped)))
                except json.JSONDecodeError:
                    pass
    return records


_PDP_ENGINE_INSTANCE: Optional[EmbeddedPolicyEngine] = None
_REMOTE_PDP_ADAPTER_INSTANCE: Optional[RemotePDPAdapter] = None
_OPA_INVALIDATION_HANDLER_INSTANCE: Optional[OPACacheInvalidationHandler] = None


def create_role_graph() -> RoleGraph:
    graph = RoleGraph.create()
    graph.add_inheritance(ROLE_ADMIN, ROLE_DEVOPS_ENGINEER)
    graph.add_inheritance(ROLE_ADMIN, ROLE_SUPPORT_AGENT)
    graph.add_inheritance(ROLE_DEVOPS_ENGINEER, ROLE_USER)
    graph.add_inheritance(ROLE_SUPPORT_AGENT, ROLE_USER)
    return graph


def get_pdp_engine() -> EmbeddedPolicyEngine:
    global _PDP_ENGINE_INSTANCE
    if _PDP_ENGINE_INSTANCE is None:
        role_graph = create_role_graph()
        cel_evaluator = CELEvaluator.create(entity_resolver=entity_resolver_instance)
        sanitizer = AuditSanitizer.create(
            masked_fields={"password", "secret", "token", "api_key", "apikey", "credential", "authorization"}
        )
        # Configure AuditManager with JsonFileAuditLogger for persistence and audit verification.
        # Additional enterprise SIEM publishers supported:
        # - ElasticCommonSchemaPublisher (audit.security.ecs)
        # - OpenTelemetryLogsPublisher
        # - SplunkHecPublisher conditionally enabled only when valid SPLUNK_HEC_URL and SPLUNK_TOKEN are provided in config.
        audit_publishers = [
            JsonFileAuditLogger.create(DEFAULT_AUDIT_LOG_FILE),
        ]
        splunk_url = config.splunk_hec_url
        splunk_token = config.splunk_token
        if splunk_url and splunk_token:
            audit_publishers.append(SplunkHecPublisher(hec_url=splunk_url, token=splunk_token))

        audit_manager = AuditManager.create(
            publishers=audit_publishers,
            sanitizer=sanitizer,
        )
        decision_cache = TwoTierDecisionCache.create(
            l1_enabled=config.cache_l1_enabled,
            l2_enabled=config.cache_l2_enabled,
            l2_ttl_seconds=config.cache_l2_ttl_seconds,
            l2_max_entries=config.cache_l2_max_entries,
        )
        engine = EmbeddedPolicyEngine.with_components(
            role_graph=role_graph,
            cel_evaluator=cel_evaluator,
            audit_manager=audit_manager,
            decision_cache=decision_cache,
        )
        engine.enforce_strict_tenant_isolation = True
        set_pii_scope(config.pii_redaction_scope)
        _PDP_ENGINE_INSTANCE = engine
        from langchain_security_extension.security_core.registry import SecurityRegistry
        SecurityRegistry.configure(pdp_engine=engine, entity_resolver=entity_resolver_instance)
    return _PDP_ENGINE_INSTANCE


def get_remote_pdp_adapter(*args: Any, **kwargs: Any) -> RemotePDPAdapter:
    global _REMOTE_PDP_ADAPTER_INSTANCE
    use_fallback = bool(kwargs.get("use_fallback", False))
    endpoint_url = str(kwargs.get("endpoint_url", config.pdp_opa_url))
    timeout_seconds = float(kwargs.get("timeout_seconds", config.pdp_opa_timeout_seconds))
    failure_threshold = int(kwargs.get("failure_threshold", config.pdp_circuit_breaker_threshold))
    recovery_seconds = float(kwargs.get("recovery_seconds", config.pdp_circuit_breaker_recovery_seconds))

    base_engine = get_pdp_engine()
    if _REMOTE_PDP_ADAPTER_INSTANCE is None or kwargs:
        adapter = RemotePDPAdapter.create(
            endpoint_url=endpoint_url,
            timeout_seconds=timeout_seconds,
            failure_threshold=failure_threshold,
            fallback_engine=base_engine if use_fallback else None,
            recovery_seconds=recovery_seconds,
            audit_manager=base_engine.audit_manager,
        )
        if not kwargs:
            _REMOTE_PDP_ADAPTER_INSTANCE = adapter
        return adapter
    return _REMOTE_PDP_ADAPTER_INSTANCE


def get_opa_cache_invalidation_handler() -> OPACacheInvalidationHandler:
    global _OPA_INVALIDATION_HANDLER_INSTANCE
    if _OPA_INVALIDATION_HANDLER_INSTANCE is None:
        _OPA_INVALIDATION_HANDLER_INSTANCE = OPACacheInvalidationHandler(pdp_engine=get_pdp_engine())
    return _OPA_INVALIDATION_HANDLER_INSTANCE


def reset_pdp_engine() -> None:
    global _PDP_ENGINE_INSTANCE, _REMOTE_PDP_ADAPTER_INSTANCE, _OPA_INVALIDATION_HANDLER_INSTANCE
    _PDP_ENGINE_INSTANCE = None
    _REMOTE_PDP_ADAPTER_INSTANCE = None
    _OPA_INVALIDATION_HANDLER_INSTANCE = None
    reset_pii_scope()
    reset_pii_sanitizer()


def security_identity_from_context(sec_ctx: Optional[SecurityContext]) -> SecurityIdentity:
    """Retrieves or resolves library SecurityIdentity directly from SecurityContext without redundant claims reparsing."""
    if sec_ctx is None:
        return SecurityIdentity.anonymous()
    return sec_ctx.to_identity(
        clearance_rank_map=CLEARANCE_RANK_MAP,
        default_clearance=DEFAULT_CLEARANCE_RANK,
    )


