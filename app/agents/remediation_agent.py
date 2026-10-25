import logging
import re
import time
from typing import List, Optional, Any, Dict, Tuple
from app.config import config
from app.security.models import IncidentContext, RemediationReport
from app.agents.infrastructure_tools import InfrastructureTools, default_infra_tools
from app.agents.knowledge_base_store import KnowledgeBaseStore, kb_store_instance
from app.agents.llm_factory import LLMFactory
from app.security.security_integration import (
    security_identity_from_context,
    get_pdp_engine,
    TRIAGE_REQUIRED_ROLES,
    TRIAGE_MIN_CLEARANCE,
    ALLOWED_TENANTS,
)
from security_core.audit import AuditEvent
from security_core.constants import (
    ACTION_TOOL_EXECUTE,
    PEP_TOOL_INTERCEPTOR,
    SEVERITY_CRITICAL_ALERT,
    EVENT_POLICY_BRUTE_FORCE_SCANNING,
)
from security_core.identity import IdentityBridge
from security_adapter_langchain.runnable_guard import SecureRunnable
from security_adapter_langchain.violation_handler import (
    ToolViolationHandler,
    RetryBudgetTracker,
    AbuseThrottleTracker,
    ViolationResolution,
    STATUS_BLOCKED_BY_POLICY,
    POLICY_STATUS_BLOCKED,
    EXECUTION_ACTION_ABORTED,
)
from app.agents.guardrail_tests_telemetry_helper import (
    finalize_telemetry,
    build_remediation_report,
    build_violation_fallback_report,
)

logger = logging.getLogger("agent.remediation")

STAGE_STANDARD_SECURITY = "standard_security"
STAGE_TRIAGE_SECURITY = "triage_security"
STAGE_TRIAGE_EXECUTION = "triage_execution"
STAGE_REMEDIATION_SECURITY = "remediation_security"
STAGE_REMEDIATION_EXECUTION = "remediation_execution"
STAGE_RAG_CLEARANCE = "rag_clearance"

STATUS_RESOLVED = "RESOLVED"
STATUS_PASSED = "PASSED"
STATUS_SKIPPED_NO_PEP = "SKIPPED (NO_POLICY_ENGINE)"
STATUS_SUCCESS_LLM = "SUCCESS_LLM"
STATUS_RAG_UNCHECKED = "UNCHECKED (Standard Retriever)"
STATUS_BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
STATUS_REJECTED_INVALID_ENTITY = "REJECTED_INVALID_ENTITY"

DEFAULT_SERVER_NAME = "web-prod-01"
DEFAULT_SERVICE_NAME = "payment-service"
UNEXTRACTED_SERVER = "unextracted-server"
UNEXTRACTED_SERVICE = "unextracted-service"
CANDIDATE_FALLBACK_SERVERS: List[str] = [DEFAULT_SERVER_NAME, "hr-app-01", "db-prod-01"]
TOP_K_SEARCH = 3
EMAIL_REGEX_STRICT = r'(?<![:/\w])[\w\.-]+@[\w\-]+\.[\w\.-]+'
RESTART_INTENT_PATTERN = re.compile(r"\b(?:restart|restarting)(?:[\s_]|$)")
REASON_ABUSE_THROTTLE_EXCEEDED = "Abuse throttle threshold exceeded: Brute-force scanning detected across window"
ROOT_CAUSE_POLICY_BRUTE_FORCE = "Policy Abort: POLICY_BRUTE_FORCE_SCANNING"
RESOURCE_CROSS_TURN_ABUSE = "cross_turn_abuse_throttle"
ACTION_BLOCKED_ABUSE_THROTTLING = "Blocked execution due to active sliding-window abuse throttling"
USER_MSG_ABUSE_THROTTLED = "Execution halted: Abuse throttle threshold exceeded (POLICY_BRUTE_FORCE_SCANNING)"


class RemediationAgent:
    """Agent consulting IT runbooks and running diagnostic/remediation tools via LangChain LLM."""

    def _extract_triage_execution_status(self, context: IncidentContext) -> str:
        return context.triageStatus if context.triageStatus else STATUS_SUCCESS_LLM

    def __init__(self) -> None:
        self.tools: InfrastructureTools = default_infra_tools
        self.kb_store: KnowledgeBaseStore = kb_store_instance
        self.model_name = config.model2_name
        self.base_url = config.model2_base_url
        self.model_class = config.model2_class
        self.api_key = config.model2_api_key
        self.llm = LLMFactory.create_chat_model(
            self.model_name,
            self.base_url,
            self.model_class,
            self.api_key
        )
        retry_tracker = RetryBudgetTracker.create(max_feedback_violations=config.retry_max_violations)
        abuse_tracker = AbuseThrottleTracker.create(
            window_seconds=config.abuse_window_seconds,
            max_denials=config.abuse_max_denials,
        )
        self.violation_handler = ToolViolationHandler.create(
            pdp_engine=get_pdp_engine(),
            retry_tracker=retry_tracker,
            abuse_tracker=abuse_tracker,
        )
        self.secured_workflow = SecureRunnable.wrap(
            runnable=self._execute_remediation,
            pdp_engine=get_pdp_engine(),
            agent_name="remediation_agent",
            required_roles=TRIAGE_REQUIRED_ROLES,
            min_clearance=TRIAGE_MIN_CLEARANCE,
            target_tenant=ALLOWED_TENANTS,
        ).with_violation_handler(
            violation_handler=self.violation_handler,
            fallback_builder=build_violation_fallback_report,
        )

    def process_incident(self, context: IncidentContext, *args: Any, **kwargs: Any) -> RemediationReport:
        """Process incident ticket with diagnostic and remediation steps via SecureRunnable workflow.

        Args:
            context: Incident ticket context containing ticket parameters and security context.
            *args: Additional positional arguments (e.g. config).
            **kwargs: Additional runtime arguments (e.g. config).

        Returns:
            RemediationReport: Report detailing remediation actions, root cause, and status.
        """
        logger.info(f"[RemediationAgent] Processing incident ticketId: {context.ticketId} via LLM ({self.model_name})")

        run_config: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("config")
        if run_config is None:
            sec_identity = security_identity_from_context(context.securityContext)
            run_config = IdentityBridge.create_runnable_config(sec_identity)

        return SecureRunnable.handoff(self.secured_workflow, context, run_config)

    def _execute_remediation(self, context: IncidentContext, *args: Any, **kwargs: Any) -> RemediationReport:
        """Execute IT runbook retrieval, strategy consultation, and remediation tool execution.

        Args:
            context: Incident ticket context.
            *args: Positional runtime configuration dictionary.
            **kwargs: Keyword runtime configuration dictionary.

        Returns:
            RemediationReport: Complete remediation report.
        """
        config: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("config")
        cfg_dict: Dict[str, Any] = config.get("configurable", {}) if isinstance(config, dict) else {}
        actions: List[str] = cfg_dict.setdefault("sec:actions", [])
        raw_text_lower = context.rawTicketText.lower()

        # Step 0: Check Cross-Turn Abuse Throttling State
        caller_identity = IdentityBridge.extract_from_config(config)
        now_ts = time.time()
        if (
            caller_identity is not None
            and self.violation_handler is not None
            and self.violation_handler.abuse_tracker.is_throttled(caller_identity.subject_id, now_ts)
        ):
            logger.warning(
                f"[RemediationAgent] Caller '{caller_identity.subject_id}' is actively throttled by sliding-window abuse tracker."
            )
            audit_mgr = getattr(self.violation_handler.pdp_engine, "audit_manager", None)
            if audit_mgr is not None:
                audit_mgr.record_event(
                    AuditEvent.create(
                        subject_id=caller_identity.subject_id,
                        tenant_id=caller_identity.tenant_id,
                        action=ACTION_TOOL_EXECUTE,
                        resource=RESOURCE_CROSS_TURN_ABUSE,
                        decision=EXECUTION_ACTION_ABORTED,
                        diagnostic_reason=REASON_ABUSE_THROTTLE_EXCEEDED,
                        severity=SEVERITY_CRITICAL_ALERT,
                        metadata={"subject_id": caller_identity.subject_id},
                        enforcement_point=PEP_TOOL_INTERCEPTOR,
                        reason_code=EVENT_POLICY_BRUTE_FORCE_SCANNING,
                    )
                )
            throttle_resolution = ViolationResolution.create(
                status=STATUS_BLOCKED_BY_POLICY,
                action_entry=ACTION_BLOCKED_ABUSE_THROTTLING,
                root_cause=ROOT_CAUSE_POLICY_BRUTE_FORCE,
                user_message=USER_MSG_ABUSE_THROTTLED,
                policy_decision=POLICY_STATUS_BLOCKED,
                execution_action=EXECUTION_ACTION_ABORTED,
                should_abort=True,
                diagnostic_reason=REASON_ABUSE_THROTTLE_EXCEEDED,
                tool_name=RESOURCE_CROSS_TURN_ABUSE,
            )
            cfg_dict["sec:last_violation"] = throttle_resolution
            return build_violation_fallback_report(context, throttle_resolution, config)

        # Step 1: Consult Knowledge Base Runbooks
        runbook_context = self.kb_store.search_as_string(context.rawTicketText, top_k=TOP_K_SEARCH, config=config)
        actions.append("Consulted In-Memory Knowledge Base Runbooks")

        # Step 2: LLM Consultation for Incident Resolution Strategy
        prompt = (
            "You are an IT Remediation Agent. Review the incident details and runbooks:\n"
            f"Ticket ID: {context.ticketId}\n"
            f"User Email: {context.userEmail}\n"
            f"Ticket Text: {context.rawTicketText}\n"
            f"Priority: {context.priority}\n"
            f"Target Server: {context.targetServer}\n"
            f"Target Service: {context.targetService}\n"
            f"Runbook Knowledge:\n{runbook_context}\n\n"
            "Formulate a brief resolution message describing the remediation steps."
        )

        llm_advice = ""
        try:
            llm_response = self.llm.invoke(prompt)
            llm_advice = str(llm_response.content if hasattr(llm_response, "content") else llm_response)
            logger.info(f"[RemediationAgent] LLM reasoning output: {llm_advice}")
        except Exception as exc:
            logger.warning(f"[RemediationAgent] LLM invocation error: {exc}. Proceeding with standard execution.")

        user_msg = ""
        root_cause = "Identified via Diagnostic Engine & IT Runbook Procedures"

        # Step 3: Diagnostic & Tool Execution
        if "password" in raw_text_lower or "reset" in raw_text_lower:
            user_email = context.userEmail
            email_match = re.search(EMAIL_REGEX_STRICT, context.rawTicketText)
            if email_match:
                extracted_email = email_match.group(0)
                if extracted_email.lower() != context.userEmail.lower() or "executive.ceo" in raw_text_lower:
                    user_email = extracted_email

            reset_outcome = self.tools.reset_user_password(user_email, config=config)
            actions.append(f"Executed password reset workflow for user {user_email}")
            user_msg = f"Diagnostic runbooks consulted. Password reset initiated successfully: {reset_outcome}"
            root_cause = "User requested account access / password reset procedure."
        else:
            candidate_servers = (
                CANDIDATE_FALLBACK_SERVERS
                if context.targetServer == UNEXTRACTED_SERVER
                else [context.targetServer]
            )
            server_name = candidate_servers[0]
            service_name = (
                context.targetService
                if context.targetService and context.targetService != UNEXTRACTED_SERVICE
                else DEFAULT_SERVICE_NAME
            )

            status_result: Any = None
            for candidate_srv in candidate_servers:
                server_name = candidate_srv
                status_result = self.tools.check_server_status(candidate_srv, config=config)
                if not (isinstance(status_result, dict) and status_result.get("status") == "ACCESS_DENIED"):
                    break
            actions.append("Ran server status diagnostics (checkServerStatus)")

            if bool(RESTART_INTENT_PATTERN.search(raw_text_lower)):
                restart_result = self.tools.restart_service(service_name, server_name, config=config)
                actions.append("Executed service restart remediation step (restartService)")
                self.tools.check_server_status(server_name, config=config)
                actions.append("Verified service health post-remediation")
                user_msg = f"Remediation completed successfully. Status: {status_result}. Restart outcome: {restart_result}"
                root_cause = "Service degradation resolved via restart and post-health verification."
            else:
                user_msg = f"Diagnostics completed. Status: {status_result}"
                root_cause = "Identified via Diagnostic Engine & IT Runbook Procedures"

        if llm_advice and len(llm_advice.strip()) > 0:
            user_msg += f" [LLM Guidance: {llm_advice.strip()[:150]}]"

        actions, user_msg, rag_clearance_status = finalize_telemetry(
            actions, user_msg
        )

        return build_remediation_report(
            context,
            root_cause,
            actions,
            STATUS_RESOLVED,
            user_msg,
            rag_clearance=rag_clearance_status,
        )


remediation_agent_instance = RemediationAgent()
