import logging
from app.security.models import RemediationReport

logger = logging.getLogger("service.notification")


class NotificationService:
    """Notification service emitting resolution alerts and ticket closure metrics."""

    def emit_resolution_notification(self, report: RemediationReport) -> None:
        logger.info(
            f"[NOTIFICATION DISPATCH] Ticket '{report.ticketId}' resolution emitted. "
            f"Status: {report.finalStatus} | Stage breakdown: {report.stageResults}"
        )


notification_service_instance = NotificationService()
