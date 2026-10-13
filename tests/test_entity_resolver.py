"""Unit tests for the EntityAttributeResolverSPI implementation in app.security.entity_resolver."""

from app.security.entity_resolver import entity_resolver_instance


def test_server_and_user_entity_resolution():
    srv_attrs = entity_resolver_instance.resolve("server", "finance-db-01")
    assert srv_attrs is not None
    assert srv_attrs["ownerDepartment"] == "FINANCE"
    assert srv_attrs["owner_department"] == "FINANCE"

    usr_attrs = entity_resolver_instance.resolve("user", "sarah.employee@enterprise.com")
    assert usr_attrs is not None
    assert usr_attrs["department"] == "HR"

    assert entity_resolver_instance.resolve("server", "nonexistent-srv-99") is None
