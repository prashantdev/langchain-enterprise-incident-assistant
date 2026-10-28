import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/tickets/health")
    assert response.status_code == 200
    assert response.json()["status"] == "UP"


def test_login_endpoint_success():
    response = client.post(
        "/api/auth/login",
        json={"email": "alex.devops@enterprise.com", "password": "password123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert token is not None and len(token) > 0


def test_login_endpoint_invalid_password():
    response = client.post(
        "/api/auth/login",
        json={"email": "alex.devops@enterprise.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401


def test_submit_ticket_unauthorized_missing_header():
    response = client.post(
        "/api/v1/tickets",
        json={
            "ticketId": "TCK-UNAUTH-001",
            "userEmail": "unknown@external.com",
            "rawTicketText": "Restart web-prod-01"
        }
    )
    assert response.status_code == 403


def test_submit_ticket_unregistered_user_blocked():
    response = client.post(
        "/api/v1/tickets",
        headers={"X-User-Email": "unknown.attacker@external-domain.com"},
        json={
            "ticketId": "TCK-UNAUTH-003",
            "userEmail": "unknown.attacker@external-domain.com",
            "rawTicketText": "Please restart db-prod-01 database connection pool immediately."
        }
    )
    assert response.status_code == 403


def test_submit_ticket_authorized_user_success():
    response = client.post(
        "/api/v1/tickets",
        headers={"X-User-Email": "alex.devops@enterprise.com"},
        json={
            "ticketId": "TCK-AUTH-001",
            "userEmail": "alex.devops@enterprise.com",
            "rawTicketText": "CRITICAL OUTAGE: payment-service on web-prod-01 is down."
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["finalStatus"] == "RESOLVED"
    assert data["stageResults"]["standard_security"] == "PASSED"


def test_remediation_handoff_entry_denial_returns_403_report(monkeypatch):
    from fastapi import Request, Response
    from app.routers.tickets import submit_ticket
    from app.agents.remediation_agent import remediation_agent_instance
    from app.security.models import TicketRequest
    from app.security.user_registry import UserRegistry
    from langchain_security_extension.security_core.exceptions import AgentAccessDeniedException, TenantIsolationError

    registry = UserRegistry()
    sec_ctx = registry.build_security_context("alex.devops@enterprise.com")
    req = TicketRequest(
        ticketId="TCK-HANDOFF-DENY-01",
        userEmail="alex.devops@enterprise.com",
        rawTicketText="Check server status on web-prod-01",
        securityContext=sec_ctx,
    )
    scope = {"type": "http", "method": "POST", "path": "/api/v1/tickets", "headers": []}
    http_req = Request(scope)

    def raise_entry_denied(*args, **kwargs):
        raise AgentAccessDeniedException.for_agent(
            "remediation_agent",
            "Clearance below remediation entry requirement",
            "INSUFFICIENT_CLEARANCE",
        )

    monkeypatch.setattr(remediation_agent_instance, "process_incident", raise_entry_denied)
    resp = Response()
    report = submit_ticket(req, http_req, resp, sec_ctx)
    assert resp.status_code == 403
    assert report.finalStatus == "BLOCKED_BY_POLICY"
    assert report.stageResults["triage_security"] == "PASSED"
    assert report.stageResults["remediation_security"] == "BLOCKED"
    assert report.stageResults["remediation_execution"] == "ABORTED"

    def raise_tenant_denied(*args, **kwargs):
        raise TenantIsolationError("remediation_agent", "Tenant mismatch", "TENANT_MISMATCH")

    monkeypatch.setattr(remediation_agent_instance, "process_incident", raise_tenant_denied)
    resp_tenant = Response()
    report_tenant = submit_ticket(req, http_req, resp_tenant, sec_ctx)
    assert resp_tenant.status_code == 403
    assert report_tenant.stageResults["remediation_security"] == "BLOCKED_TENANT"


def test_logout_endpoint_success():
    login_resp = client.post(
        "/api/auth/login",
        json={"email": "alex.devops@enterprise.com", "password": "password123"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_resp.status_code == 200
    data = logout_resp.json()
    assert data["status"] == "SUCCESS"
    assert data["subject_id"] == "alex.devops@enterprise.com"

