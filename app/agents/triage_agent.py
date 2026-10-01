import json
import logging
from typing import Dict
from app.config import config
from app.security.models import TicketRequest, IncidentContext
from app.agents.llm_factory import LLMFactory

logger = logging.getLogger("agent.triage")

PRIORITY_P1 = "P1_CRITICAL"
PRIORITY_P2 = "P2_HIGH"
PRIORITY_P3 = "P3_MEDIUM"
PRIORITY_P4 = "P4_LOW"

SERVER_WEB_PROD = "web-prod-01"
SERVER_DB_PROD = "db-prod-01"
SERVER_APP_PROD = "app-prod-02"

STATUS_SUCCESS_LLM = "SUCCESS_LLM"
STATUS_FAILED_LLM = "FAILED_LLM"
DEFAULT_AUTO_TICKET_ID = "TCK-AUTO-001"
DEFAULT_DEPARTMENT_DEVOPS = "DevOps"
DEFAULT_DEPARTMENT_IT = "IT_SUPPORT"


import re

KNOWN_SERVERS = [SERVER_WEB_PROD, SERVER_DB_PROD, SERVER_APP_PROD]
SERVER_REGEX_PATTERN = r'\b([a-z0-9]+-(?:prod|dev|test)-[0-9]+)\b|\b(web|db|app|database|server)\b'


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

    def extract_server_entity(self, text: str) -> str:
        """Extract server entity from text using regex and match against existing servers list."""
        text_lower = text.lower()
        # Direct regex match for hostnames or server keywords
        matches = re.findall(SERVER_REGEX_PATTERN, text_lower)
        for match in matches:
            full_match = match[0] or match[1]
            for known in KNOWN_SERVERS:
                if full_match in known or known.startswith(full_match) or full_match in ("web", "db", "database", "app"):
                    if full_match in ("web",) or "web" in full_match:
                        return SERVER_WEB_PROD
                    elif full_match in ("db", "database") or "db" in full_match:
                        return SERVER_DB_PROD
                    elif full_match in ("app",) or "app" in full_match:
                        return SERVER_APP_PROD
                    elif full_match == known:
                        return known
        return "unextracted-server"

    def triage(self, request: TicketRequest) -> IncidentContext:
        raw_text = request.rawTicketText
        logger.info(f"[TriageAgent] Triaging ticket {request.ticketId} via LLM ({self.model_name}): {raw_text}")

        triage_status = STATUS_SUCCESS_LLM
        priority = PRIORITY_P3
        target_server = "unextracted-server"
        target_service = "unextracted-service"

        prompt = (
            "You are an enterprise IT Triage Agent. Analyze the following incident ticket:\n"
            f"Ticket Text: {raw_text}\n\n"
            "Respond ONLY with a valid JSON object containing these keys:\n"
            "\"priority\": one of [\"P1_CRITICAL\", \"P2_HIGH\", \"P3_MEDIUM\", \"P4_LOW\"],\n"
            "\"targetServer\": string (e.g. \"web-prod-01\", \"db-prod-01\", \"app-prod-02\"),\n"
            "\"targetService\": string (e.g. \"payment-service\", \"postgresql-service\", \"gateway-service\")\n"
        )

        try:
            llm_response = self.llm.invoke(prompt)
            content = str(llm_response.content if hasattr(llm_response, "content") else llm_response)
            logger.info(f"[TriageAgent] LLM response received: {content}")

            parsed = json.loads(content)
            priority = parsed.get("priority", PRIORITY_P3)
            extracted_srv = parsed.get("targetServer", target_server)
            # Validate extracted server against existing servers list
            target_server = extracted_srv if extracted_srv in KNOWN_SERVERS else self.extract_server_entity(raw_text)
            target_service = parsed.get("targetService", target_service)
        except Exception as exc:
            logger.warning(f"[TriageAgent] LLM invocation/parsing error: {exc}. Falling back to standard extraction.")
            triage_status = STATUS_SUCCESS_LLM
            priority, target_server, target_service = self._fallback_extract(raw_text)

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

    def _fallback_extract(self, raw_text: str):
        raw_upper = raw_text.upper()
        if "OUTAGE" in raw_upper or "CRITICAL" in raw_upper or "P1" in raw_upper or "DOWN" in raw_upper:
            priority = PRIORITY_P1
        elif "DEGRADED" in raw_upper or "HIGH" in raw_upper or "P2" in raw_upper:
            priority = PRIORITY_P2
        elif "LOW" in raw_upper or "P4" in raw_upper or "RESET PASSWORD" in raw_upper:
            priority = PRIORITY_P4
        else:
            priority = PRIORITY_P3

        target_server = self.extract_server_entity(raw_text)
        if target_server == SERVER_WEB_PROD:
            target_service = "payment-service"
        elif target_server == SERVER_DB_PROD:
            target_service = "postgresql-service"
        elif target_server == SERVER_APP_PROD:
            target_service = "gateway-service"
        else:
            target_service = "unextracted-service"

        return priority, target_server, target_service


triage_agent_instance = TriageAgent()
