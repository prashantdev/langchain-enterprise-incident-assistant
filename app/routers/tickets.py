import logging
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status
from app.security.models import TicketRequest, RemediationReport, SecurityContext
from app.security.auth import get_current_security_context
from app.security.user_registry import user_registry_instance
from app.security.master_data import CLEARANCE_UNAUTHENTICATED
from app.agents.triage_agent import triage_agent_instance
from app.agents.remediation_agent import remediation_agent_instance
from app.notifications.notification_service import notification_service_instance
from app.agents.guardrail_tests_telemetry_helper import (
    enforce_ingestion_security,
    build_entry_access_denied_report,
)
from app.security.security_integration import security_identity_from_context
from security_core.identity import IdentityBridge
from security_core.exceptions import AgentAccessDeniedException, TenantIsolationError

logger = logging.getLogger("router.tickets")
router = APIRouter(prefix="/api/v1/tickets", tags=["Tickets"])


@router.get("/health")
def health_check():
    return {"status": "UP", "service": "Enterprise IT Incident & Service Desk Assistant"}


@router.post("", response_model=RemediationReport)
@router.post("/", response_model=RemediationReport)
def submit_ticket(
    request: TicketRequest,
    req_context: Request,
    response: Response,
    sec_context: SecurityContext = Depends(get_current_security_context),
):
    if not request.ticketId or not request.ticketId.strip():
        request.ticketId = f"TCK-{str(uuid.uuid4())[:8]}"

    if not request.submittedAt:
        request.submittedAt = datetime.now(timezone.utc).isoformat()

    if sec_context and sec_context.clearanceLevel != CLEARANCE_UNAUTHENTICATED:
        request.userEmail = sec_context.userEmail
    elif not sec_context or sec_context.clearanceLevel == CLEARANCE_UNAUTHENTICATED:
        sec_context = user_registry_instance.build_security_context(request.userEmail)

    request.securityContext = sec_context

    logger.info(f"Incoming Ticket Received: ticketId={request.ticketId}, user={request.userEmail}")
    logger.info(f"SecurityContext attached: {sec_context}")

    ingestion_report = enforce_ingestion_security(request, sec_context, response)
    if ingestion_report:
        return ingestion_report

    sec_identity = security_identity_from_context(sec_context)
    run_config = IdentityBridge.create_runnable_config(sec_identity)

    # Triage Phase (Guarded by SecureRunnable Entry PEP)
    try:
        incident_context = triage_agent_instance.triage(request, config=run_config)
    except TenantIsolationError as exc:
        logger.warning(f"Triage entry tenant isolation violation: {exc}")
        return build_entry_access_denied_report(request, exc, response, "BLOCKED_TENANT")
    except AgentAccessDeniedException as exc:
        logger.warning(f"Triage entry access denied: {exc}")
        return build_entry_access_denied_report(request, exc, response, "BLOCKED")

    logger.info(
        f"Triage Phase Completed: priority={incident_context.priority}, "
        f"targetServer={incident_context.targetServer}"
    )

    # Remediation Phase (In-band SecureRunnable.handoff preserving L1 cache, entity cache, and callbacks)
    try:
        report = remediation_agent_instance.process_incident(incident_context, config=run_config)
    except TenantIsolationError as exc:
        logger.warning(f"Remediation handoff tenant isolation violation: {exc}")
        return build_entry_access_denied_report(incident_context, exc, response, "BLOCKED_TENANT", stage="remediation")
    except AgentAccessDeniedException as exc:
        logger.warning(f"Remediation handoff entry access denied: {exc}")
        return build_entry_access_denied_report(incident_context, exc, response, "BLOCKED", stage="remediation")

    logger.info(f"Remediation Phase Completed: status={report.finalStatus}")

    # Notification Dispatch
    notification_service_instance.emit_resolution_notification(report)

    if report.stageResults and report.stageResults.get("remediation_security") in ("BLOCKED_POLICY", "BLOCKED_TENANT", "BLOCKED"):
        if response:
            response.status_code = status.HTTP_403_FORBIDDEN
        return report

    return report

