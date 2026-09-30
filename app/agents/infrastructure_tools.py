import logging
from datetime import datetime, timezone
from typing import Optional
from langchain_core.tools import tool
from app.security.user_registry import user_registry_instance

logger = logging.getLogger("agent.infratools")


class InfrastructureTools:
    """Diagnostic and remediation tools for IT Infrastructure management."""

    def __init__(self, user_registry=None):
        if user_registry is None:
            user_registry = user_registry_instance
        self.user_registry = user_registry

    def check_server_status(self, server_name: str) -> str:
        """Accepts target server hostname; returns operational status, CPU utilization, memory usage, and active service name."""
        logger.info(f"[TOOL EXECUTION] checkServerStatus for server: {server_name}")
        if not server_name or not server_name.strip():
            return "Error: Invalid or null serverName provided."
        
        clean_server = server_name.lower().strip()
        if "web-prod-01" in clean_server or "web" in clean_server:
            return "Server: web-prod-01 | Status: CRASHED | CPU: 88% | Memory: 96% | ActiveService: payment-service"
        elif "db-prod-01" in clean_server or "db" in clean_server:
            return "Server: db-prod-01 | Status: DEGRADED | CPU: 75% | Memory: 82% | ActiveService: postgresql-service"
        elif "app-prod-02" in clean_server:
            return "Server: app-prod-02 | Status: RUNNING | CPU: 42% | Memory: 50% | ActiveService: gateway-service"
        else:
            return f"Server: {server_name} | Status: UNKNOWN / NOT_FOUND | CPU: 0% | Memory: 0% | ActiveService: none"

    def get_user_entitlements(self, email: str) -> str:
        """Accepts user corporate email address; queries user registry and returns department, roles, and status."""
        logger.info(f"[TOOL EXECUTION] getUserEntitlements for user email: {email}")
        if not email or not email.strip():
            return "Error: Email address required."
        
        user = self.user_registry.find_by_email(email)
        if user is not None:
            return f"User: {user.email} | Department: {user.department} | Roles: {user.roles} | Clearance: {user.clearanceLevel} | Status: ACTIVE"
        return f"User: {email} | Department: UNKNOWN | Roles: NONE | Clearance: NONE | Status: NOT_FOUND / UNAUTHORIZED"

    def restart_service(self, service_name: str, server_name: str) -> str:
        """Accepts target service name and server hostname; attempts mutative service restart."""
        logger.info(f"[TOOL EXECUTION] restartService serviceName: {service_name} on serverName: {server_name}")
        if not service_name or not server_name:
            return "Error: Both serviceName and serverName are required."
        
        now_iso = datetime.now(timezone.utc).isoformat()
        return f"SUCCESS: Restarted service '{service_name}' on host '{server_name}' at {now_iso}. Service status is now RUNNING."

    def reset_user_password(self, email: str) -> str:
        """Accepts corporate user email address; triggers password reset workflow."""
        logger.info(f"[TOOL EXECUTION] resetUserPassword for user email: {email}")
        if not email or not email.strip():
            return "Error: User email required for password reset."
        
        now_iso = datetime.now(timezone.utc).isoformat()
        temp_token_id = f"TMP-{abs(hash(email))}-{int(datetime.now().timestamp() * 1000) % 10000}"
        return f"SUCCESS: Password reset initiated for {email} at {now_iso}. Temporary access token {temp_token_id} dispatched to user's registered MFA device."


default_infra_tools = InfrastructureTools()
