"""
Unit and integration tests for Spec 5 Security Audit and Observability features.
"""

import os
import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException
from app.security.auth import get_current_security_context
from app.security.models import SecurityContext
from app.security.security_integration import get_pdp_engine, get_audit_events, DEFAULT_AUDIT_LOG_FILE
from langchain_security_extension.security_core.audit import AuditEvent, AuditManager, AuditSanitizer

TEST_USER_EMAIL = "sarah.employee@enterprise.com"
TEST_TENANT_CORP = "tenant-default"
TEST_TENANT_FOREIGN = "CORP_FOREIGN"
TEST_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TEST_SPAN_ID = "00f067aa0ba902b7"


@pytest.mark.anyio
async def test_auth_w3c_traceparent_correlation():
    mock_request = MagicMock()
    mock_request.url.path = "/api/v1/tickets"
    mock_request.method = "POST"
    mock_request.headers = {"traceparent": f"00-{TEST_TRACE_ID}-{TEST_SPAN_ID}-01"}

    mock_credentials = MagicMock()
    mock_credentials.credentials = "valid_token"

    sample_sec_ctx = SecurityContext(
        userEmail=TEST_USER_EMAIL,
        department="HR",
        assignedRoles=["ROLE_USER"],
        clearanceLevel="1",
        tenantId=TEST_TENANT_CORP,
    )

    with patch("app.security.auth.extract_security_context_from_request", return_value=sample_sec_ctx):
        result = await get_current_security_context(mock_request, mock_credentials)
        assert result.userEmail == TEST_USER_EMAIL
        assert result.tenantId == TEST_TENANT_CORP


@pytest.mark.anyio
async def test_auth_tenant_isolation_boundary_violation_audit():
    from app.routers.tickets import submit_ticket
    from app.security.models import TicketRequest
    from fastapi import Response

    mock_request = MagicMock()
    mock_request.url.path = "/api/v1/tickets"
    mock_request.method = "POST"
    mock_request.headers = {"traceparent": f"00-{TEST_TRACE_ID}-{TEST_SPAN_ID}-01"}
    mock_response = Response()

    foreign_sec_ctx = SecurityContext(
        userEmail=TEST_USER_EMAIL,
        department="HR",
        assignedRoles=["ROLE_USER"],
        clearanceLevel="1",
        tenantId=TEST_TENANT_FOREIGN,
    )

    t_request = TicketRequest(
        ticketId="TCK-TENANT-001",
        userEmail=TEST_USER_EMAIL,
        rawTicketText="Query internal runbooks for foreign tenant",
    )

    report = submit_ticket(
        request=t_request,
        req_context=mock_request,
        response=mock_response,
        sec_context=foreign_sec_ctx,
    )
    assert mock_response.status_code == 403
    assert report.stageResults["remediation_security"] == "BLOCKED_TENANT"

    audit_events = [
        e for e in get_audit_events(DEFAULT_AUDIT_LOG_FILE)
        if getattr(e, "reason_code", None) == "TENANT_BOUND_VIOLATION"
    ]
    assert len(audit_events) > 0


def test_pii_sanitization_in_audit_events():
    from langchain_security_extension.security_core.pii import get_pii_scope
    pdp_engine = get_pdp_engine()
    audit_mgr = pdp_engine.audit_manager
    assert get_pii_scope() == "audit_only"

    # Create an audit event with sensitive PII in payload_snapshot and diagnostic_reason
    raw_payload = {
        "email": "user.secret@enterprise.com",
        "phone": "+1-555-123-4567",
        "ssn": "123-45-6789",
        "nested": {
            "credit_card": "4532015112830366",  # Valid Luhn VISA
            "api_key": "AKIAIOSFODNN7EXAMPLE",
        },
    }
    event = AuditEvent.create(
        subject_id="test-subject",
        tenant_id="CORP_MAIN",
        action="QUERY",
        resource="runbook://db-access",
        decision="PERMIT",
        diagnostic_reason="Access permitted for user user.secret@enterprise.com with key AKIAIOSFODNN7EXAMPLE",
        severity="INFO",
        metadata=raw_payload,
        enforcement_point="RUNNABLE_GUARD",
        reason_code="PII_AUDIT_TEST",
    )

    audit_mgr.record_event(event)

    # Verify that the event captured in the json logger has sanitized payload and diagnostic reason
    recorded_events = [e for e in get_audit_events(DEFAULT_AUDIT_LOG_FILE) if getattr(e, "reason_code", None) == "PII_AUDIT_TEST"]
    assert len(recorded_events) > 0
    rec = recorded_events[-1]

    assert rec.payload_snapshot["email"] == "[REDACTED]"
    assert rec.payload_snapshot["phone"] == "[REDACTED]"
    assert rec.payload_snapshot["ssn"] == "[REDACTED]"
    assert rec.payload_snapshot["nested"]["credit_card"] == "[REDACTED]"
    assert rec.payload_snapshot["nested"]["api_key"] == "[REDACTED]"
    assert "[REDACTED]" in rec.diagnostic_reason

