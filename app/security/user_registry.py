from typing import Dict, Optional, List
from app.security.models import User, SecurityContext
from app.security.master_data import (
    ROLE_GUEST,
    ROLE_USER,
    ROLE_ADMIN,
    ROLE_DEVOPS_ENGINEER,
    ROLE_EMPLOYEE,
    ROLE_SUPPORT_AGENT,
    CLEARANCE_TOP_SECRET,
    CLEARANCE_SECRET,
    CLEARANCE_STANDARD,
    CLEARANCE_UNAUTHENTICATED,
    DEFAULT_TENANT_ID,
    DEPT_UNKNOWN,
    ANONYMOUS_USER_EMAIL,
)

USER_ALEX_EMAIL = "alex.devops@enterprise.com"
USER_SARAH_EMAIL = "sarah.employee@enterprise.com"
USER_JOHN_EMAIL = "john.support@enterprise.com"
DEFAULT_DEMO_PASSWORD = "password123"


class UserRegistry:
    """In-memory user registry matching the enterprise user repository."""

    def __init__(self) -> None:
        self.user_map: Dict[str, User] = {}
        self._init_default_users()

    def _init_default_users(self) -> None:
        self.register_user(
            User(
                email=USER_ALEX_EMAIL,
                name="Alex Rivera",
                department="DevOps",
                roles=[ROLE_DEVOPS_ENGINEER, ROLE_ADMIN, ROLE_USER],
                clearanceLevel=CLEARANCE_TOP_SECRET,
                password=DEFAULT_DEMO_PASSWORD,
            )
        )
        self.register_user(
            User(
                email=USER_SARAH_EMAIL,
                name="Sarah Jenkins",
                department="HR",
                roles=[ROLE_USER, ROLE_EMPLOYEE],
                clearanceLevel=CLEARANCE_STANDARD,
                password=DEFAULT_DEMO_PASSWORD,
            )
        )
        self.register_user(
            User(
                email=USER_JOHN_EMAIL,
                name="John Support",
                department="IT_SUPPORT",
                roles=[ROLE_SUPPORT_AGENT, ROLE_USER],
                clearanceLevel=CLEARANCE_SECRET,
                password=DEFAULT_DEMO_PASSWORD,
            )
        )

    def register_user(self, user: User) -> None:
        key = user.email.lower().strip()
        self.user_map[key] = user

    def find_by_email(self, email: Optional[str]) -> Optional[User]:
        if not email:
            return None
        key = email.lower().strip()
        return self.user_map.get(key)

    def build_security_context(self, email: Optional[str]) -> SecurityContext:
        user = self.find_by_email(email)
        if user is not None:
            return SecurityContext(
                userEmail=user.email,
                department=user.department,
                assignedRoles=user.roles,
                clearanceLevel=user.clearanceLevel,
                tenantId=DEFAULT_TENANT_ID,
            )
        fallback_email = email if email else ANONYMOUS_USER_EMAIL
        return SecurityContext(
            userEmail=fallback_email,
            department=DEPT_UNKNOWN,
            assignedRoles=[ROLE_GUEST],
            clearanceLevel=CLEARANCE_UNAUTHENTICATED,
            tenantId=DEFAULT_TENANT_ID,
        )

    def evict_subject_from_pdp_cache(self, email: Optional[str]) -> int:
        return 0


user_registry_instance = UserRegistry()
