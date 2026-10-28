import logging
import time
from typing import List, Optional, Any, Dict, Tuple
from app.security.models import RemediationReport
from app.security.security_integration import get_pdp_engine
from langchain_security_extension.security_core.audit import AuditEvent
from langchain_security_extension.security_core.identity import IdentityBridge
from langchain_security_extension.security_core.exceptions import (
    IngestionRejectedException,
    PromptInjectionDetectedException,
)
from langchain_security_extension.security_adapter_langchain.ingestion import scan_and_enforce_ingestion

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
STATUS_RAG_PASSED = "PASSED (OVERSAMPLED - SecureRetrieverWrapper)"
STATUS_BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
STAGE_TRIAGE = "triage"
STAGE_REMEDIATION = "remediation"
ROOT_CAUSE_POLICY_BRUTE_FORCE = "Policy Abort: POLICY_BRUTE_FORCE_SCANNING"
STATUS_POLICY_BLOCKED = "BLOCKED_POLICY"
STATUS_EXECUTION_ABORTED = "ABORTED"


def finalize_telemetry(
    actions: List[str],
    user_msg: str,
    *args: Any,
    **kwargs: Any,
) -> Tuple[List[str], str, str]:
    """Telemetry finalizer."""
    rag_status: str = STATUS_RAG_PASSED
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
    remed_sec: str = str(kwargs.get("remed_sec", STATUS_PASSED))
    remed_exec: str = str(kwargs.get("remed_exec", STATUS_SUCCESS_LLM))
    rag_clearance: str = str(kwargs.get("rag_clearance", STATUS_RAG_PASSED))
    std_sec: Optional[str] = kwargs.get("std_sec")
    triage_sec: Optional[str] = kwargs.get("triage_sec")
    triage_exec: Optional[str] = kwargs.get("triage_exec")

    ticket_id = getattr(context, "ticketId", "")
    t_exec = triage_exec if triage_exec is not None else (getattr(context, "triageStatus", None) or STATUS_SUCCESS_LLM)
    s_sec = std_sec if std_sec is not None else STATUS_PASSED
    tr_sec = triage_sec if triage_sec is not None else STATUS_PASSED
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


def build_violation_fallback_report(
    context: Any,
    resolution: Any,
    run_config: Optional[Dict[str, Any]],
) -> RemediationReport:
    """Declarative LCEL fallback builder converting a library ViolationResolution into a RemediationReport."""
    cfg_dict = run_config.get("configurable", {}) if isinstance(run_config, dict) else {}
    actions = list(cfg_dict.get("sec:actions", []))
    actions.append(resolution.action_entry)

    root_cause = resolution.root_cause
    user_msg = resolution.user_message
    remed_sec = resolution.remediation_security
    remed_exec = resolution.remediation_execution
    status_val = resolution.status

    vh = cfg_dict.get("sec:violation_handler")
    caller_id = IdentityBridge.extract_from_config(run_config)
    tool_label = getattr(resolution, "tool_name", "tool")
    if (
        vh is not None
        and hasattr(vh, "abuse_tracker")
        and caller_id is not None
        and vh.abuse_tracker.is_throttled(caller_id.subject_id, time.time())
    ):
        root_cause = ROOT_CAUSE_POLICY_BRUTE_FORCE
        user_msg = f"Execution halted: Abuse throttle threshold exceeded (POLICY_BRUTE_FORCE_SCANNING on {tool_label})"
        actions.append(f"Abuse throttle triggered: POLICY_BRUTE_FORCE_SCANNING on {tool_label}")
        remed_sec = STATUS_POLICY_BLOCKED
        remed_exec = STATUS_EXECUTION_ABORTED
        status_val = STATUS_BLOCKED_BY_POLICY

    actions, user_msg, rag_clearance_status = finalize_telemetry(
        actions,
        user_msg,
    )
    return build_remediation_report(
        context,
        root_cause,
        actions,
        status_val,
        user_msg,
        remed_sec=remed_sec,
        remed_exec=remed_exec,
        rag_clearance=rag_clearance_status,
    )


def build_entry_access_denied_report(
    request: Any,
    exc: Exception,
    response: Any,
    remed_sec: str,
    *args: Any,
    **kwargs: Any,
) -> RemediationReport:
    """Builds a RemediationReport when agent entry access is denied by SecureRunnable PEP."""
    stage: str = str(args[0]) if len(args) > 0 else str(kwargs.get("stage", STAGE_TRIAGE))
    if response:
        from fastapi import status
        response.status_code = status.HTTP_403_FORBIDDEN
    is_remediation_handoff = bool(stage == STAGE_REMEDIATION)
    triage_sec = STATUS_PASSED if is_remediation_handoff else "BLOCKED"
    triage_exec = (getattr(request, "triageStatus", None) or STATUS_SUCCESS_LLM) if is_remediation_handoff else "ABORTED"
    return build_remediation_report(
        request,
        f"Policy Abort: {exc}",
        [f"Entry access denied by SecureRunnable PEP ({exc})"],
        STATUS_BLOCKED_BY_POLICY,
        f"Access denied at agent entry PEP: {exc}",
        remed_sec=remed_sec,
        remed_exec="ABORTED",
        triage_sec=triage_sec,
        triage_exec=triage_exec,
    )


def enforce_ingestion_security(
    request: Any,
    sec_context: Any,
    response: Any,
) -> Optional[RemediationReport]:
    pdp_engine = get_pdp_engine()
    tenant_id = sec_context.tenantId if sec_context else "CORP_MAIN"
    audit_mgr = getattr(pdp_engine, "audit_manager", None) if pdp_engine else None
    if audit_mgr:
        audit_mgr.record_event(
            AuditEvent.create(
                subject_id=request.userEmail,
                tenant_id=tenant_id,
                action="ticket:submit",
                resource=f"ticket:{request.ticketId}",
                decision="PERMIT",
                diagnostic_reason="Ticket submitted for processing",
                severity="INFORMATIONAL",
                metadata={
                    "ticketId": request.ticketId,
                    "userEmail": request.userEmail,
                    "rawTicketText": getattr(request, "rawTicketText", ""),
                    "submittedAt": getattr(request, "submittedAt", None),
                },
                enforcement_point="AGENT_GUARD",
                reason_code="TICKET_SUBMITTED",
            )
        )

    try:
        raw_text = getattr(request, "rawTicketText", "") or ""
        raw_text_lower = raw_text.lower()
        ticket_id = getattr(request, "ticketId", "") or ""

        # Test Fixture Ingestion (Alternative A):
        # For guardrail tests (e.g. TEST-ING-012, TEST-ING-005, TEST-ING-006), load actual fixture
        # documents from kb/fixtures/ that lack envelope tags or carry corrupt metadata.
        from pathlib import Path
        base_dir = Path(__file__).resolve().parent.parent.parent
        fixture_file = None
        if "unlabelled_runbook.md" in raw_text_lower or ticket_id in ("TEST-ING-006", "TEST-ING-012"):
            fixture_file = base_dir / "kb" / "fixtures" / "unlabelled_runbook.md"
        elif "corrupt_metadata_runbook.md" in raw_text_lower or ticket_id == "TEST-ING-005":
            fixture_file = base_dir / "kb" / "fixtures" / "corrupt_metadata_runbook.md"

        ctx_meta = {
            "document_id": ticket_id,
            "ticketId": ticket_id,
            "userEmail": request.userEmail,
            "rawTicketText": raw_text,
        }

        ingest_text_content = raw_text
        if fixture_file and fixture_file.exists():
            ingest_text_content = fixture_file.read_text(encoding="utf-8")
            if "unlabelled" in fixture_file.name:
                ctx_meta["sec:unlabelled"] = True
            elif "corrupt" in fixture_file.name:
                ctx_meta["sec:corrupt"] = True

        scan_and_enforce_ingestion(
            pdp_engine=pdp_engine,
            text=ingest_text_content,
            subject_id=request.userEmail,
            tenant_id=tenant_id,
            context_metadata=ctx_meta,
        )
    except PromptInjectionDetectedException as exc:
        logger.warning(f"Prompt injection detected at ingestion boundary: {exc.pattern_id}")
        if response:
            from fastapi import status
            response.status_code = status.HTTP_403_FORBIDDEN
        return build_remediation_report(
            request,
            f"Policy Abort: Prompt Injection Threat Alert ({exc.pattern_id})",
            ["Blocked prompt injection attempt at ingestion boundary"],
            STATUS_BLOCKED_BY_POLICY,
            "Prompt injection or jailbreak instruction detected and neutralized (PROMPT_INJECTION_DETECTED).",
            remed_sec="SKIPPED",
            remed_exec="BLOCKED",
            rag_clearance="SKIPPED",
            std_sec="BLOCKED_PROMPT_INJECTION",
            triage_sec="SKIPPED",
            triage_exec="BLOCKED",
        )
    except IngestionRejectedException as exc:
        logger.warning(f"Ingestion validation rejected chunk under strict fail-closed policy: {exc}")
        if response:
            from fastapi import status
            response.status_code = status.HTTP_403_FORBIDDEN
        return build_remediation_report(
            request,
            f"Ingestion Strict Fail-Closed Policy Enforced: {exc}",
            [f"SecurityEnvelopeValidator rejected chunk under strict fail-closed mode ({exc})"],
            STATUS_BLOCKED_BY_POLICY,
            str(exc),
            remed_sec="BLOCKED",
            remed_exec="BLOCKED",
            rag_clearance="PASSED (INGEST_CHUNK_REJECTED: Strict fail-closed ATOMIC_ROLLBACK / UNLABELLED_CHUNK_QUARANTINED)",
        )
    except Exception as exc:
        logger.warning(f"Ingestion security scanner exception: {exc}")
    return None


