import pytest
from fastapi import HTTPException
from app.security.auth import check_required_roles, check_required_department
from app.security.models import SecurityContext


def test_check_required_roles_pass():
    ctx = SecurityContext(
        userEmail="alex.devops@enterprise.com",
        department="DevOps",
        assignedRoles=["ROLE_DEVOPS_ENGINEER", "ROLE_ADMIN"],
        clearanceLevel="TOP_SECRET"
    )
    check_required_roles(ctx, ["ROLE_ADMIN"])


def test_check_required_roles_fail():
    ctx = SecurityContext(
        userEmail="sarah.employee@enterprise.com",
        department="HR",
        assignedRoles=["ROLE_EMPLOYEE"],
        clearanceLevel="STANDARD"
    )
    with pytest.raises(HTTPException) as exc_info:
        check_required_roles(ctx, ["ROLE_ADMIN"])
    assert exc_info.value.status_code == 403


def test_check_required_department_pass():
    ctx = SecurityContext(
        userEmail="sarah.employee@enterprise.com",
        department="HR",
        assignedRoles=["ROLE_EMPLOYEE"],
        clearanceLevel="STANDARD"
    )
    check_required_department(ctx, "HR")


def test_check_required_department_admin_bypass():
    ctx = SecurityContext(
        userEmail="alex.devops@enterprise.com",
        department="DevOps",
        assignedRoles=["ROLE_ADMIN"],
        clearanceLevel="TOP_SECRET"
    )
    check_required_department(ctx, "HR")
