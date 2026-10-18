import logging
from typing import List, Optional, Any, Dict, Tuple
from app.security.models import RemediationReport

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


def finalize_telemetry(
    actions: List[str],
    user_msg: str,
    *args: Any,
    **kwargs: Any,
) -> Tuple[List[str], str, str]:
    """Telemetry finalizer."""
    rag_status: str = STATUS_RAG_UNCHECKED
    if len(args) > 0:
        rag_status = str(args[0])
    elif "default_rag_status" in kwargs:
        rag_status = str(kwargs["default_rag_status"])
    return actions, user_msg, rag_status


def build_remediation_report(
    context: Any,
    root_cause: str,
    actions: List[str],
    final_status: str,
    user_msg: str,
    *args: Any,
    **kwargs: Any,
) -> RemediationReport:
    """Builds RemediationReport."""
    remed_sec: str = str(kwargs.get("remed_sec", STATUS_SKIPPED_NO_PEP))
    remed_exec: str = str(kwargs.get("remed_exec", STATUS_SUCCESS_LLM))
    rag_clearance: str = str(kwargs.get("rag_clearance", STATUS_RAG_UNCHECKED))
    std_sec: Optional[str] = kwargs.get("std_sec")
    triage_sec: Optional[str] = kwargs.get("triage_sec")
    triage_exec: Optional[str] = kwargs.get("triage_exec")

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

