import logging
from datetime import datetime, timezone
from typing import Optional, Any, Dict
from langchain_core.tools import tool
from app.security.user_registry import user_registry_instance

from app.security.exceptions import ToolEntityValidationError

logger = logging.getLogger("agent.infratools")

DIAGNOSTIC_INVALID_ENTITY = "INVALID_ENTITY_REMEDIATION"
INVALID_SERVER_KEYWORDS = ["fake", "nonexistent"]

ROLE_USER = "ROLE_USER"
ROLE_SUPPORT_AGENT = "ROLE_SUPPORT_AGENT"
ROLE_DEVOPS_ENGINEER = "ROLE_DEVOPS_ENGINEER"
ROLE_ADMIN = "ROLE_ADMIN"

CLEARANCE_STANDARD = 0


class InfrastructureTools:
    """Diagnostic and remediation tools for IT Infrastructure management."""

    KNOWN_SERVERS = [
        "web-prod-01",
        "db-prod-01",
        "app-prod-02",
        "devops-prod-01",
        "srv-devops-east-01",
        "hr-app-01",
        "finance-db-01",
    ]

    def __init__(self, user_registry: Optional[Any] = None):
        if user_registry is None:
            user_registry = user_registry_instance
        self.user_registry = user_registry

    def _validate_server_name(self, tool_name: str, server_name: Optional[str]) -> str:
        if not server_name or not server_name.strip():
            raise ToolEntityValidationError.for_tool(
                tool_name,
                "Invalid or empty server name provided.",
                DIAGNOSTIC_INVALID_ENTITY
            )
        
        clean_server = server_name.lower().strip()
        if any(keyword in clean_server for keyword in INVALID_SERVER_KEYWORDS):
            raise ToolEntityValidationError.for_tool(
                tool_name,
                f"Invalid entity or server name: '{server_name}'",
                DIAGNOSTIC_INVALID_ENTITY
            )

        if not any(known in clean_server for known in self.KNOWN_SERVERS):
            raise ToolEntityValidationError.for_tool(
                tool_name,
                f"Server entity '{server_name}' does not exist in asset inventory.",
                DIAGNOSTIC_INVALID_ENTITY
            )

        return clean_server

    def check_server_status(self, server_name: str, config: Optional[Dict[str, Any]] = None) -> str:
        """Accepts target server hostname; returns operational status, CPU utilization, memory usage, and active service name."""
        logger.info(f"[TOOL EXECUTION] checkServerStatus for server: {server_name}")
        clean_server = self._validate_server_name("checkServerStatus", server_name)
        
        if "web-prod-01" in clean_server or "web" in clean_server:
            return "Server: web-prod-01 | Status: CRASHED | CPU: 88% | Memory: 96% | ActiveService: payment-service"
        elif "db-prod-01" in clean_server or "db" in clean_server:
            return "Server: db-prod-01 | Status: DEGRADED | CPU: 75% | Memory: 82% | ActiveService: postgresql-service"
        elif "app-prod-02" in clean_server:
            return "Server: app-prod-02 | Status: RUNNING | CPU: 42% | Memory: 50% | ActiveService: gateway-service"
        elif "devops-prod-01" in clean_server or "srv-devops-east-01" in clean_server:
            return f"Server: {clean_server} | Status: RUNNING | CPU: 35% | Memory: 45% | ActiveService: ci-cd-service"
        else:
            return f"Server: {server_name} | Status: UNKNOWN / NOT_FOUND | CPU: 0% | Memory: 0% | ActiveService: none"

    def get_user_entitlements(self, email: str, config: Optional[Dict[str, Any]] = None) -> str:
        """Accepts user corporate email address; queries user registry and returns department, roles, and status."""
        logger.info(f"[TOOL EXECUTION] getUserEntitlements for user email: {email}")
        if not email or not email.strip():
            return "Error: Email address required."
        
        user = self.user_registry.find_by_email(email)
        if user is not None:
            return f"User: {user.email} | Department: {user.department} | Roles: {user.roles} | Clearance: {user.clearanceLevel} | Status: ACTIVE"
        return f"User: {email} | Department: UNKNOWN | Roles: NONE | Clearance: NONE | Status: NOT_FOUND / UNAUTHORIZED"

    def restart_service(self, service_name: str, server_name: str, config: Optional[Dict[str, Any]] = None) -> str:
        """Accepts target service name and server hostname; attempts mutative service restart."""
        logger.info(f"[TOOL EXECUTION] restartService serviceName: {service_name} on serverName: {server_name}")
        if not service_name or not service_name.strip():
            return "Error: Both serviceName and serverName are required."
        
        self._validate_server_name("restartService", server_name)
        
        now_iso = datetime.now(timezone.utc).isoformat()
        return f"SUCCESS: Restarted service '{service_name}' on host '{server_name}' at {now_iso}. Service status is now RUNNING."

    def reset_user_password(self, email: str, config: Optional[Dict[str, Any]] = None) -> str:
        """Accepts corporate user email address; triggers password reset workflow."""
        logger.info(f"[TOOL EXECUTION] resetUserPassword for user email: {email}")
        if not email or not email.strip():
            return "Error: User email required for password reset."

        now_iso = datetime.now(timezone.utc).isoformat()
        temp_token_id = f"TMP-{abs(hash(email))}-{int(datetime.now().timestamp() * 1000) % 10000}"
        return f"SUCCESS: Password reset initiated for {email} at {now_iso}. Temporary access token {temp_token_id} dispatched to user's registered MFA device."


default_infra_tools = InfrastructureTools()
