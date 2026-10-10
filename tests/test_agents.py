import pytest
from app.security.models import TicketRequest
from app.security.user_registry import UserRegistry
from app.agents.triage_agent import TriageAgent
from app.agents.infrastructure_tools import InfrastructureTools
from app.agents.knowledge_base_store import KnowledgeBaseStore
from app.agents.remediation_agent import RemediationAgent


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


def test_infrastructure_tools():
    registry = UserRegistry()
    tools = InfrastructureTools(registry)

    status_res = tools.check_server_status("web-prod-01")
    assert "web-prod-01" in status_res
    assert "CRASHED" in status_res

    entitlements_res = tools.get_user_entitlements("alex.devops@enterprise.com")
    assert "DevOps" in entitlements_res

    restart_res = tools.restart_service("payment-service", "web-prod-01")
    assert "SUCCESS" in restart_res

    pwd_res = tools.reset_user_password("sarah.employee@enterprise.com")
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



