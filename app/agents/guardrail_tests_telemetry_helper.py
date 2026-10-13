import logging
from typing import List, Optional, Any, Dict, Tuple
from app.security.models import IncidentContext, RemediationReport

logger = logging.getLogger("agent.remediation.telemetry")

STAGE_STANDARD_SECURITY = "standard_security"
STAGE_TRIAGE_SECURITY = "triage_security"
STAGE_TRIAGE_EXECUTION = "triage_execution"
STAGE_REMEDIATION_SECURITY = "remediation_security"
STAGE_REMEDIATION_EXECUTION = "remediation_execution"
STAGE_RAG_CLEARANCE = "rag_clearance"

STATUS_PASSED = "PASSED"
STATUS_SKIPPED_NO_PEP = "SKIPPED (NO_POLICY_ENGINE)"
STATUS_SUCCESS_LLM = "SUCCESS_LLM"
STATUS_RAG_UNCHECKED = "UNCHECKED (Standard Retriever)"
STATUS_BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class BasicInMemoryAuditLogger:
    """Baseline in-memory audit logger for unhardened application."""

    def __init__(self) -> None:
        self.events: List[Any] = []

    def get_events(self) -> List[Any]:
        return list(self.events)

    def log_event(self, event: Any) -> None:
        self.events.append(event)


def finalize_telemetry(
    actions: List[str],
    user_msg: str,
    raw_text_lower: str,
    sec_identity: Any,
    in_mem_logger: Optional[Any],
    initial_events_count: int,
    run_config: Dict[str, Any],
    default_rag_status: str = STATUS_RAG_UNCHECKED,
) -> Tuple[List[str], str, str]:
    """Baseline telemetry finalizer for unhardened master branch."""
    return actions, user_msg, default_rag_status


def build_remediation_report(
    context: Any,
    root_cause: str,
    actions: List[str],
    final_status: str,
    user_msg: str,
    remed_sec: str = STATUS_SKIPPED_NO_PEP,
    remed_exec: str = STATUS_SUCCESS_LLM,
    rag_clearance: str = STATUS_RAG_UNCHECKED,
    std_sec: Optional[str] = None,
    triage_sec: Optional[str] = None,
    triage_exec: Optional[str] = None,
) -> RemediationReport:
    """Builds RemediationReport with common default stage results for master branch."""
    ticket_id = getattr(context, "ticketId", "")
    t_exec = triage_exec if triage_exec is not None else (getattr(context, "triageStatus", None) or STATUS_SUCCESS_LLM)
    s_sec = std_sec if std_sec is not None else STATUS_PASSED
    tr_sec = triage_sec if triage_sec is not None else STATUS_SKIPPED_NO_PEP
    return RemediationReport(
        ticketId=ticket_id,
        rootCause=root_cause,
        actionsTaken=actions,
        finalStatus=final_status,
        userFacingResolutionMessage=user_msg,
        stageResults={
            STAGE_STANDARD_SECURITY: s_sec,
            STAGE_TRIAGE_SECURITY: tr_sec,
            STAGE_TRIAGE_EXECUTION: t_exec,
            STAGE_REMEDIATION_SECURITY: remed_sec,
            STAGE_REMEDIATION_EXECUTION: remed_exec,
            STAGE_RAG_CLEARANCE: rag_clearance,
        },
    )


def enforce_ingestion_security(
    request: Any,
    sec_context: Any,
    response: Any,
) -> Optional[RemediationReport]:
    """Baseline ingestion security handler for unhardened master branch (no-op)."""
    return None

