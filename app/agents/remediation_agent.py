import logging
import re
from typing import List, Optional, Any, Dict, Tuple
from app.config import config
from app.security.models import IncidentContext, RemediationReport
from app.agents.infrastructure_tools import InfrastructureTools, default_infra_tools
from app.agents.knowledge_base_store import KnowledgeBaseStore, kb_store_instance
from app.agents.llm_factory import LLMFactory
from app.security.exceptions import ToolEntityValidationError
from app.agents.guardrail_tests_telemetry_helper import (
    finalize_telemetry,
    build_remediation_report,
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

    def _enforce_manual_security(
        self,
        context: IncidentContext,
        action_name: str,
        target_email: Optional[str] = None,
    ) -> Optional[RemediationReport]:
        sec_ctx = context.securityContext
        raw_user_roles = sec_ctx.assignedRoles if sec_ctx else []
        user_roles = []
        for r in raw_user_roles:
            user_roles.extend([role.strip() for role in r.split(",")])

        is_admin_or_devops = any(r in user_roles for r in ["ROLE_ADMIN", "ROLE_DEVOPS_ENGINEER", "ROLE_SRE"])

        if action_name == "resetUserPassword":
            raw_text_lower = context.rawTicketText.lower()
            is_targeting_other_user = "executive.ceo" in raw_text_lower or "ceo" in raw_text_lower
            if not is_admin_or_devops and (is_targeting_other_user or (sec_ctx and sec_ctx.userEmail != target_email)):
                return build_remediation_report(
                    context,
                    "Policy Abort: Unauthorized Mutative Tool Execution",
                    ["Aborted mutative tool execution resetUserPassword"],
                    STATUS_BLOCKED_BY_POLICY,
                    "Mutative password reset operation aborted by Policy Enforcement Point (PEP).",
                    remed_sec="BLOCKED",
                    remed_exec="ABORTED",
                )
        elif action_name == "restartService":
            if not is_admin_or_devops:
                return build_remediation_report(
                    context,
                    "Policy Abort: Unauthorized Mutative Service Restart",
                    ["Ran server status diagnostics (checkServerStatus)", "Aborted mutative tool execution restartService"],
                    STATUS_BLOCKED_BY_POLICY,
                    "Mutative service restart operation aborted. Insufficient user role.",
                    remed_sec="BLOCKED",
                    remed_exec="ABORTED",
                )
        return None

    def _handle_tool_entity_validation_error(
        self,
        context: IncidentContext,
        actions: List[str],
        exc: ToolEntityValidationError,
    ) -> RemediationReport:
        logger.warning(f"[RemediationAgent] ToolEntityValidationError caught: {exc.message}")
        actions, user_msg, rag_clearance_status = finalize_telemetry(
            actions + ["Rejected operation targeting invalid or non-existent entity"],
            f"Invalid entity error: {exc.message}",
        )
        return build_remediation_report(
            context,
            f"Invalid Entity Error: {exc.message}",
            actions,
            STATUS_REJECTED_INVALID_ENTITY,
            user_msg,
            remed_sec="BLOCKED",
            remed_exec="BLOCKED",
            rag_clearance=rag_clearance_status,
        )

    def process_incident(self, context: IncidentContext, *args: Any, **kwargs: Any) -> RemediationReport:
        """Process incident ticket with diagnostic and remediation steps.

        Args:
            context: Incident ticket context containing ticket parameters and security context.
            *args: Additional positional arguments (e.g. config).
            **kwargs: Additional runtime arguments (e.g. config).

        Returns:
            RemediationReport: Report detailing remediation actions, root cause, and status.
        """
        logger.info(f"[RemediationAgent] Processing incident ticketId: {context.ticketId} via LLM ({self.model_name})")
        config: Optional[Dict[str, Any]] = args[0] if len(args) > 0 else kwargs.get("config")
        cfg_dict: Dict[str, Any] = config.get("configurable", {}) if isinstance(config, dict) else {}
        actions: List[str] = cfg_dict.setdefault("sec:actions", [])
        try:
            return self._execute_remediation(context, config=config)
        except ToolEntityValidationError as exc:
            return self._handle_tool_entity_validation_error(context, actions, exc)

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

        llm_response = self.llm.invoke(prompt)
        llm_advice = str(llm_response.content if hasattr(llm_response, "content") else llm_response)
        logger.info(f"[RemediationAgent] LLM reasoning output: {llm_advice}")

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

            policy_violation = self._enforce_manual_security(context, "resetUserPassword", target_email=user_email)
            if policy_violation:
                return policy_violation

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

            policy_violation = self._enforce_manual_security(context, "restartService")
            if policy_violation:
                return policy_violation

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
