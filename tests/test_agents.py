import pytest
from app.security.models import TicketRequest
from app.security.user_registry import UserRegistry
from app.agents.triage_agent import TriageAgent
from app.agents.infrastructure_tools import InfrastructureTools
from app.agents.knowledge_base_store import KnowledgeBaseStore
from app.agents.remediation_agent import RemediationAgent


from app.security.security_integration import security_identity_from_context


def test_triage_agent_classification():
    registry = UserRegistry()
    sec_ctx = registry.build_security_context("alex.devops@enterprise.com")
    request = TicketRequest(
        ticketId="TCK-TEST-001",
        userEmail="alex.devops@enterprise.com",
        rawTicketText="CRITICAL OUTAGE: payment-service on web-prod-01 is unresponsive!",
        securityContext=sec_ctx
    )
    triage_agent = TriageAgent()
    incident_ctx = triage_agent.triage(request)

    assert incident_ctx.priority == "P1_CRITICAL"
    assert incident_ctx.targetServer == "web-prod-01"
    assert incident_ctx.targetService == "payment-service"


def test_infrastructure_tools(caplog):
    registry = UserRegistry()
    tools = InfrastructureTools(registry)
    sec_ctx = registry.build_security_context("alex.devops@enterprise.com")
    sec_identity = security_identity_from_context(sec_ctx)

    import logging
    with caplog.at_level(logging.INFO, logger="agent.infratools"):
        status_res = tools.check_server_status("web-prod-01", security_identity=sec_identity)
        assert "web-prod-01" in status_res
        assert "CRASHED" in status_res
        assert f"checkServerStatus subject: {sec_identity.subject_id}, tenant: {sec_identity.tenant_id}" in caplog.text

        caplog.clear()
        restart_res = tools.restart_service("payment-service", "web-prod-01", security_identity=sec_identity)
        assert "SUCCESS" in restart_res
        assert f"restartService subject: {sec_identity.subject_id}, tenant: {sec_identity.tenant_id}" in caplog.text

    entitlements_res = tools.get_user_entitlements("alex.devops@enterprise.com", security_identity=sec_identity)
    assert "DevOps" in entitlements_res

    pwd_res = tools.reset_user_password("sarah.employee@enterprise.com", security_identity=sec_identity)
    assert "SUCCESS" in pwd_res



def test_infrastructure_tools_invalid_entity():
    from app.security.exceptions import ToolEntityValidationError
    registry = UserRegistry()
    tools = InfrastructureTools(registry)

    with pytest.raises(ToolEntityValidationError) as exc_info:
        tools._validate_server_name("check_server_status", "fake-server-01")
    assert exc_info.value.diagnostic_reason == "INVALID_ENTITY_REMEDIATION"

    with pytest.raises(ToolEntityValidationError) as exc_info:
        tools._validate_server_name("check_server_status", "nonexistent-box")
    assert exc_info.value.diagnostic_reason == "INVALID_ENTITY_REMEDIATION"

    with pytest.raises(ToolEntityValidationError) as exc_info:
        tools._validate_server_name("check_server_status", "")
    assert exc_info.value.diagnostic_reason == "INVALID_ENTITY_REMEDIATION"


def test_agent_entry_and_handoff_propagation():
    from langchain_security_extension.security_core.identity import IdentityBridge

    registry = UserRegistry()
    sec_ctx = registry.build_security_context("alex.devops@enterprise.com")
    sec_identity = security_identity_from_context(sec_ctx)
    run_config = IdentityBridge.create_runnable_config(sec_identity)

    triage_agent = TriageAgent()
    remediation_agent = RemediationAgent()

    req = TicketRequest(
        ticketId="TCK-HANDOFF-01",
        userEmail="alex.devops@enterprise.com",
        rawTicketText="Check server status on web-prod-01",
        securityContext=sec_ctx,
    )
    incident_ctx = triage_agent.triage(req, config=run_config)
    assert run_config["configurable"].get("sec:entry_verified:triage_agent") is True

    report = remediation_agent.process_incident(incident_ctx, config=run_config)
    assert run_config["configurable"].get("sec:handoff_propagated") is True
    assert run_config["configurable"].get("sec:entry_verified:remediation_agent") is True
    assert report.finalStatus == "RESOLVED"


def test_infrastructure_tools_schema_hiding():
    from langchain_security_extension.security_adapter_langchain.tool_decorator import get_tool_schema

    tools = InfrastructureTools()
    for tool_method in (
        tools.check_server_status,
        tools.get_user_entitlements,
        tools.restart_service,
        tools.reset_user_password,
    ):
        schema = get_tool_schema(tool_method)
        assert schema["schema_hiding_verified"] is True
        assert "config" not in schema["parameters"]["properties"]
        assert "security_identity" not in schema["parameters"]["properties"]
        assert "runnable_config" not in schema["parameters"]["properties"]
        assert "config" not in schema["parameters"].get("required", [])
        assert "security_identity" not in schema["parameters"].get("required", [])
        assert "runnable_config" not in schema["parameters"].get("required", [])



def test_cel_restart_service_clearance_across_departments():
    from langchain_security_extension.security_core.identity import IdentityBridge
    from langchain_security_extension.security_core.exceptions import ToolExecutionDeniedError

    registry = UserRegistry()
    tools = InfrastructureTools(registry)

    admin_ctx = registry.build_security_context("alex.devops@enterprise.com")
    admin_id = security_identity_from_context(admin_ctx)
    admin_cfg = IdentityBridge.create_runnable_config(admin_id)
    assert admin_id.clearance_level == 3

    for srv in ("hr-app-01", "finance-db-01", "web-prod-01"):
        res = tools.restart_service("app-service", srv, config=admin_cfg)
        assert "SUCCESS: Restarted service" in res

    devops_ctx = registry.build_security_context("alex.devops@enterprise.com")
    devops_ctx.assignedRoles = ["ROLE_DEVOPS_ENGINEER"]
    devops_ctx.clearanceLevel = "SECRET"
    devops_id = security_identity_from_context(devops_ctx)
    devops_cfg = IdentityBridge.create_runnable_config(devops_id)
    assert devops_id.clearance_level == 2

    own_res = tools.restart_service("ci-cd-service", "devops-prod-01", config=devops_cfg)
    assert "SUCCESS: Restarted service" in own_res

    with pytest.raises(ToolExecutionDeniedError):
        tools.restart_service("postgresql-service", "finance-db-01", config=devops_cfg)





