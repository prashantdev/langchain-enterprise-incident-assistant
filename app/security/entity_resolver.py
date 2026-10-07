"""
Entity Attribute Resolver SPI implementation for incident assistant domain entities.

NOTE FOR THE READER:
This is a contrived demonstrator implementation that loads server asset mappings
and attributes from an in-memory dictionary. In a real-world enterprise system,
you will have production-grade systems like LDAP, Microsoft Active Directory,
or a proper REST interface / library to resolve entity attributes from your asset management database.
"""

from typing import Dict, Any
from security_core.cel_evaluator import EntityAttributeResolverSPI

DEFAULT_SERVER_DEPARTMENT = "IT_OPERATIONS"

SERVER_DEPARTMENT_MAP = {
    "web-prod-01": "IT_OPERATIONS",
    "db-prod-01": "IT_OPERATIONS",
    "app-prod-02": "IT_OPERATIONS",
    "devops-prod-01": "IT_OPERATIONS",
    "srv-devops-east-01": "IT_OPERATIONS",
    "hr-app-01": "HR",
    "finance-db-01": "FINANCE",
}


class IncidentAssistantEntityResolver(EntityAttributeResolverSPI):
    """
    Hydrates infrastructure entity attributes (e.g. server ownerDepartment)
    for Common Expression Language (CEL) parameter evaluation.
    """

    def resolve(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        if entity_type == "server":
            return self._resolve_server_entity(entity_id)
        return self._resolve_unknown_entity(entity_type, entity_id)

    def _resolve_server_entity(self, server_name: str) -> Dict[str, Any]:
        clean_name = server_name.lower().strip() if server_name else ""
        if not clean_name or clean_name not in SERVER_DEPARTMENT_MAP:
            return None
        department = SERVER_DEPARTMENT_MAP[clean_name]
        return {
            "name": clean_name,
            "ownerDepartment": department,
            "department": department,
            "isKnown": True,
        }

    def _resolve_unknown_entity(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        return {
            "id": entity_id,
            "type": entity_type,
            "isKnown": False,
        }


entity_resolver_instance = IncidentAssistantEntityResolver()
