import pytest
from app.security.user_registry import UserRegistry, USER_ALEX_EMAIL, USER_SARAH_EMAIL


def test_user_registry_default_users():
    registry = UserRegistry()
    alex = registry.find_by_email(USER_ALEX_EMAIL)
    assert alex is not None
    assert alex.department == "DevOps"
    assert "ROLE_ADMIN" in alex.roles
    assert alex.clearanceLevel == "TOP_SECRET"


def test_user_registry_case_insensitive():
    registry = UserRegistry()
    sarah = registry.find_by_email("SARAH.EMPLOYEE@ENTERPRISE.COM  ")
    assert sarah is not None
    assert sarah.email == USER_SARAH_EMAIL


def test_user_registry_security_context_registered():
    registry = UserRegistry()
    ctx = registry.build_security_context(USER_ALEX_EMAIL)
    assert ctx.userEmail == USER_ALEX_EMAIL
    assert ctx.department == "DevOps"
    assert "ROLE_DEVOPS_ENGINEER" in ctx.assignedRoles


def test_user_registry_security_context_unregistered():
    registry = UserRegistry()
    ctx = registry.build_security_context("unknown.user@external.com")
    assert ctx.userEmail == "unknown.user@external.com"
    assert ctx.clearanceLevel == "UNAUTHENTICATED"
    assert "ROLE_GUEST" in ctx.assignedRoles


def test_user_registry_revocation_evicts_pdp_cache():
    from app.agents.infrastructure_tools import InfrastructureTools
    from app.security.security_integration import (
        get_pdp_engine,
        security_identity_from_context,
        get_audit_events,
        DEFAULT_AUDIT_LOG_FILE,
    )
    from langchain_security_extension.security_core.identity import IdentityBridge
    from langchain_security_extension.security_core.constants import EVENT_CACHE_EVICTED

    registry = UserRegistry()
    pdp = get_pdp_engine()
    sec_ctx = registry.build_security_context("john.support@enterprise.com")
    sec_id = security_identity_from_context(sec_ctx)
    cfg = IdentityBridge.create_runnable_config(sec_id)

    tools = InfrastructureTools(registry)
    tools.check_server_status("web-prod-01", config=cfg)
    tools.check_server_status("web-prod-01", config=cfg)
    assert cfg["configurable"].get("sec:pdp_cache_hit") is True

    evicted = registry.revoke_user_roles("john.support@enterprise.com")
    assert evicted >= 1
    events = get_audit_events(DEFAULT_AUDIT_LOG_FILE)
    assert any(getattr(e, "reason_code", "") == EVENT_CACHE_EVICTED for e in events)

