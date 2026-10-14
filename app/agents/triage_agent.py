import re
import json
import logging
from typing import Dict, Optional, Any
from app.config import config
from app.security.models import TicketRequest, IncidentContext
from app.agents.infrastructure_tools import InfrastructureTools
from app.agents.llm_factory import LLMFactory

logger = logging.getLogger("agent.triage")

PRIORITY_P1 = "P1_CRITICAL"
PRIORITY_P2 = "P2_HIGH"
PRIORITY_P3 = "P3_MEDIUM"
PRIORITY_P4 = "P4_LOW"

STATUS_SUCCESS_LLM = "SUCCESS_LLM"
STATUS_FAILED_LLM = "FAILED_LLM"
DEFAULT_AUTO_TICKET_ID = "TCK-AUTO-001"
DEFAULT_DEPARTMENT_DEVOPS = "DevOps"
DEFAULT_DEPARTMENT_IT = "IT_SUPPORT"
IGNORED_SERVER_TOKENS = {
    "server",
    "servers",
    "checkserverstatus",
    "restartservice",
    "getuserentitlements",
    "resetuserpassword",
}


class TriageAgent:
    """Agent analyzing incident ticket text to classify priority and target infrastructure using LangChain LLM."""

    def __init__(self) -> None:
        self.model_name = config.model1_name
        self.base_url = config.model1_base_url
        self.model_class = config.model1_class
        self.api_key = config.model1_api_key
        self.llm = LLMFactory.create_chat_model(
            self.model_name,
            self.base_url,
            self.model_class,
            self.api_key
        )

    def _extract_explicit_server_from_text(self, raw_text: str) -> Optional[str]:
        if not raw_text:
            return None
        raw_lower = raw_text.lower()
        for known_srv in InfrastructureTools.KNOWN_SERVERS:
            if known_srv in raw_lower:
                return known_srv
        matched_tokens = re.findall(
            r'[a-zA-Z0-9\-_]*(?:null-|unresolved-|fake-|nonexistent)[a-zA-Z0-9\-_]*',
            raw_text,
            re.IGNORECASE,
        )
        if matched_tokens:
            return matched_tokens[0]
        return None

    def triage(self, request: TicketRequest, *args: Any, **kwargs: Any) -> IncidentContext:
        raw_text = request.rawTicketText
        logger.info(f"[TriageAgent] Triaging ticket {request.ticketId} via LLM ({self.model_name}): {raw_text}")

        triage_status = STATUS_SUCCESS_LLM
        priority = PRIORITY_P3
        target_server = "unextracted-server"
        target_service = "unextracted-service"
        explicit_server = self._extract_explicit_server_from_text(raw_text)

        prompt = (
            "You are an enterprise IT Triage Agent. Analyze the following incident ticket:\n"
            f"Ticket Text: {raw_text}\n\n"
            "Respond ONLY with a valid JSON object containing these keys:\n"
            "\"priority\": one of [\"P1_CRITICAL\", \"P2_HIGH\", \"P3_MEDIUM\", \"P4_LOW\"],\n"
            "\"targetServer\": string (e.g. \"web-prod-01\", \"db-prod-01\", \"app-prod-02\", or unextracted server string),\n"
            "\"targetService\": string (e.g. \"payment-service\", \"postgresql-service\", \"gateway-service\")\n"
        )

        try:
            llm_response = self.llm.invoke(prompt)
            content = str(llm_response.content if hasattr(llm_response, "content") else llm_response)
            logger.info(f"[TriageAgent] LLM response received: {content}")

            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            parsed = json.loads(content)
            raw_p = str(parsed.get("priority", PRIORITY_P3)).upper().replace(" ", "_").replace("-", "_")
            if "P1" in raw_p:
                priority = PRIORITY_P1
            elif "P2" in raw_p:
                priority = PRIORITY_P2
            elif "P4" in raw_p:
                priority = PRIORITY_P4
            else:
                priority = PRIORITY_P3
            extracted_srv = str(parsed.get("targetServer", ""))
            target_service = str(parsed.get("targetService", target_service))

            if explicit_server is not None:
                target_server = explicit_server
            elif extracted_srv in InfrastructureTools.KNOWN_SERVERS and extracted_srv.lower() in raw_text.lower():
                target_server = extracted_srv
            elif any(token in extracted_srv.lower() for token in ("null-", "unresolved-", "fake-", "nonexistent")):
                target_server = extracted_srv
            else:
                target_server = InfrastructureTools.KNOWN_SERVERS[0] if InfrastructureTools.KNOWN_SERVERS else "web-prod-01"
        except Exception as exc:
            logger.error(f"[TriageAgent] LLM service is unreachable or failed during triage processing: {exc}")
            triage_status = STATUS_FAILED_LLM
            raw_upper = raw_text.upper()
            if "CRITICAL" in raw_upper or "OUTAGE" in raw_upper or "P1" in raw_upper:
                priority = PRIORITY_P1
            elif "HIGH" in raw_upper or "P2" in raw_upper:
                priority = PRIORITY_P2
            elif "LOW" in raw_upper or "P4" in raw_upper:
                priority = PRIORITY_P4
            matched_services = re.findall(r'[a-zA-Z0-9\-_]+-service', raw_text, re.IGNORECASE)
            if matched_services:
                target_service = matched_services[0].lower()
            if explicit_server is not None:
                target_server = explicit_server
            else:
                matched_servers = re.findall(r'[a-zA-Z0-9\-_]*(?:server|prod|devops|app|db)[a-zA-Z0-9\-_]*', raw_text, re.IGNORECASE)
                valid_srvs = [s for s in matched_servers if s.lower() not in IGNORED_SERVER_TOKENS]
                if valid_srvs:
                    target_server = valid_srvs[0]

        entities: Dict[str, str] = {
            "userEmail": request.userEmail,
            "targetServer": target_server
        }

        department = DEFAULT_DEPARTMENT_DEVOPS if "prod" in target_server else DEFAULT_DEPARTMENT_IT

        return IncidentContext(
            ticketId=request.ticketId or DEFAULT_AUTO_TICKET_ID,
            userEmail=request.userEmail,
            rawTicketText=raw_text,
            priority=priority,
            targetServer=target_server,
            targetService=target_service,
            department=department,
            triageStatus=triage_status,
            entities=entities,
            securityContext=request.securityContext,
        )


triage_agent_instance = TriageAgent()

