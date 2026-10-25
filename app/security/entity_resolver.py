"""
Entity Attribute Resolver SPI implementation for incident assistant domain entities.

NOTE FOR THE READER:
This is a contrived demonstrator implementation that loads server asset mappings
and attributes from an in-memory dictionary. In a real-world enterprise system,
you will have production-grade systems like LDAP, Microsoft Active Directory,
or a proper REST interface / library to resolve entity attributes from your asset management database.
"""

from typing import Dict, Any, Optional
from security_core.cel_evaluator import EntityAttributeResolverSPI
from app.security.user_registry import user_registry_instance

DEFAULT_SERVER_DEPARTMENT = "IT_OPERATIONS"

SERVER_DEPARTMENT_MAP: Dict[str, str] = {
    "web-prod-01": "IT_OPERATIONS",
    "db-prod-01": "IT_OPERATIONS",
    "app-prod-02": "IT_OPERATIONS",
    "devops-prod-01": "DevOps",
    "srv-devops-east-01": "DevOps",
    "hr-app-01": "HR",
    "finance-db-01": "FINANCE",
}


class IncidentAssistantEntityResolver(EntityAttributeResolverSPI):
    """
    Hydrates infrastructure and identity entity attributes (e.g. server ownerDepartment,
    user department/clearance) for Common Expression Language (CEL) parameter evaluation.
    """

    def resolve(self, entity_type: str, entity_id: str) -> Optional[Dict[str, Any]]:
        if entity_type == "server":
            return self._resolve_server_entity(entity_id)
        if entity_type == "user":
            return self._resolve_user_entity(entity_id)
        return None

    def _resolve_server_entity(self, server_name: str) -> Optional[Dict[str, Any]]:
        clean_name = server_name.lower().strip() if server_name else ""
        if not clean_name or clean_name not in SERVER_DEPARTMENT_MAP:
            return None
        department = SERVER_DEPARTMENT_MAP[clean_name]
        return {
            "name": clean_name,
            "ownerDepartment": department,
            "owner_department": department,
            "department": department,
            "isKnown": True,
            "is_known": True,
        }

    def _resolve_user_entity(self, email: str) -> Optional[Dict[str, Any]]:
        clean_email = email.lower().strip() if email else ""
        if not clean_email:
            return None
        user = user_registry_instance.find_by_email(clean_email)
        if user is None:
            return None
        return {
            "email": user.email,
            "name": user.name,
            "department": user.department,
            "ownerDepartment": user.department,
            "owner_department": user.department,
            "roles": list(user.roles),
            "clearanceLevel": user.clearanceLevel,
            "clearance_level": user.clearanceLevel,
            "isKnown": True,
            "is_known": True,
        }


entity_resolver_instance = IncidentAssistantEntityResolver()

