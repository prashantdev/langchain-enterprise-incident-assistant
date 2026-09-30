import pytest
from app.security.user_registry import UserRegistry, USER_ALEX_EMAIL, USER_SARAH_EMAIL


def test_user_registry_default_users():
    registry = UserRegistry()
    alex = registry.find_by_email(USER_ALEX_EMAIL)
    assert alex is not None
    assert alex.department == "DevOps"
    assert "ROLE_ADMIN" in alex.roles
    assert alex.clearanceLevel == "TOP_SECRET"


def test_user_registry_case_insensitive():
    registry = UserRegistry()
    sarah = registry.find_by_email("SARAH.EMPLOYEE@ENTERPRISE.COM  ")
    assert sarah is not None
    assert sarah.email == USER_SARAH_EMAIL


def test_user_registry_security_context_registered():
    registry = UserRegistry()
    ctx = registry.build_security_context(USER_ALEX_EMAIL)
    assert ctx.userEmail == USER_ALEX_EMAIL
    assert ctx.department == "DevOps"
    assert "ROLE_DEVOPS_ENGINEER" in ctx.assignedRoles


def test_user_registry_security_context_unregistered():
    registry = UserRegistry()
    ctx = registry.build_security_context("unknown.user@external.com")
    assert ctx.userEmail == "unknown.user@external.com"
    assert ctx.clearanceLevel == "UNAUTHENTICATED"
    assert "ROLE_GUEST" in ctx.assignedRoles
