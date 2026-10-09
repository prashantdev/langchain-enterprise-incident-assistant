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
    context: IncidentContext,
    root_cause: str,
    actions: List[str],
    final_status: str,
    user_msg: str,
    remed_sec: str = STATUS_SKIPPED_NO_PEP,
    remed_exec: str = STATUS_SUCCESS_LLM,
    rag_clearance: str = STATUS_RAG_UNCHECKED,
) -> RemediationReport:
    """Builds RemediationReport with common default stage results for master branch."""
    triage_exec = context.triageStatus if context.triageStatus else STATUS_SUCCESS_LLM
    return RemediationReport(
        ticketId=context.ticketId,
        rootCause=root_cause,
        actionsTaken=actions,
        finalStatus=final_status,
        userFacingResolutionMessage=user_msg,
        stageResults={
            STAGE_STANDARD_SECURITY: STATUS_PASSED,
            STAGE_TRIAGE_SECURITY: STATUS_SKIPPED_NO_PEP,
            STAGE_TRIAGE_EXECUTION: triage_exec,
            STAGE_REMEDIATION_SECURITY: remed_sec,
            STAGE_REMEDIATION_EXECUTION: remed_exec,
            STAGE_RAG_CLEARANCE: rag_clearance,
        },
    )


def handle_tool_execution_denied(
    exc: Any,
    context: IncidentContext,
    actions: List[str],
    raw_text_lower: str,
    sec_identity: Any,
    in_mem_logger: Optional[Any],
    initial_events_count: int,
    run_config: Dict[str, Any],
) -> RemediationReport:
    """Fallback handler for tool execution denied exceptions on master branch."""
    actions, user_msg, rag_status = finalize_telemetry(
        actions + [f"Aborted tool execution ({getattr(exc, 'tool_name', 'tool')})"],
        f"Tool execution denied: {getattr(exc, 'message', str(exc))}",
        raw_text_lower, sec_identity, in_mem_logger, initial_events_count, run_config
    )
    return build_remediation_report(
        context,
        f"Policy Abort: {getattr(exc, 'message', 'Tool Execution Denied')}",
        actions,
        STATUS_BLOCKED_BY_POLICY,
        user_msg,
        remed_sec="BLOCKED",
        remed_exec="ABORTED",
        rag_clearance=rag_status,
    )
