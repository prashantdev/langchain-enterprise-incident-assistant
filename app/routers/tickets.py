import logging
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status
from app.security.models import TicketRequest, RemediationReport, SecurityContext
from app.security.auth import get_current_security_context
from app.security.user_registry import user_registry_instance
from app.agents.triage_agent import triage_agent_instance
from app.agents.remediation_agent import remediation_agent_instance
from app.notifications.notification_service import notification_service_instance

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
    sec_context: SecurityContext = Depends(get_current_security_context),
    response: Response = None
):
    if not request.ticketId or not request.ticketId.strip():
        request.ticketId = f"TCK-{str(uuid.uuid4())[:8]}"

    if not request.submittedAt:
        request.submittedAt = datetime.now(timezone.utc).isoformat()

    if sec_context and sec_context.clearanceLevel != "UNAUTHENTICATED":
        request.userEmail = sec_context.userEmail
    elif not sec_context or sec_context.clearanceLevel == "UNAUTHENTICATED":
        sec_context = user_registry_instance.build_security_context(request.userEmail)

    request.securityContext = sec_context

    logger.info(f"Incoming Ticket Received: ticketId={request.ticketId}, user={request.userEmail}")
    logger.info(f"SecurityContext attached: {sec_context}")

    # Triage Phase
    incident_context = triage_agent_instance.triage(request)
    logger.info(
        f"Triage Phase Completed: priority={incident_context.priority}, "
        f"targetServer={incident_context.targetServer}"
    )

    # Remediation Phase
    report = remediation_agent_instance.process_incident(incident_context)
    logger.info(f"Remediation Phase Completed: status={report.finalStatus}")

    # Notification Dispatch
    notification_service_instance.emit_resolution_notification(report)

    if report.stageResults and report.stageResults.get("remediation_security") == "BLOCKED_POLICY":
        if response:
            response.status_code = status.HTTP_403_FORBIDDEN
        return report

    return report
