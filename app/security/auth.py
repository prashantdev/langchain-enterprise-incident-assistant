import logging
import json
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import Request, HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.security.models import SecurityContext, User
from app.security.user_registry import user_registry_instance

HEADER_USER_EMAIL = "X-User-Email"
CLEARANCE_UNAUTHENTICATED = "UNAUTHENTICATED"
ROLE_GUEST = "ROLE_GUEST"
HEALTH_PATH_SUFFIX = "/health"
DECISION_ALLOWED = "ALLOWED"

logger = logging.getLogger("security.auth")
security_bearer = HTTPBearer(auto_error=False)


def extract_user_email_from_request(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    """Extract user email from X-User-Email header or Authorization Bearer token."""
    email_header = request.headers.get(HEADER_USER_EMAIL)
    if email_header and email_header.strip():
        return email_header.strip()
    
    if credentials and credentials.credentials:
        token = credentials.credentials
        # For simple token auth, token can be user email or email:password token
        if "@" in token:
            return token.strip()
    return None


async def get_current_security_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> SecurityContext:
    """
    FastAPI dependency enforcing HTTP Request Security Filter behavior matching Java implementation.
    Checks X-User-Email header / Bearer token, validates against UserRegistry, logs audit entry,
    and returns SecurityContext or raises HTTP 403 Forbidden.
    """
    path = request.url.path
    if path.endswith(HEALTH_PATH_SUFFIX):
        return user_registry_instance.build_security_context(None)

    user_email = extract_user_email_from_request(request, credentials)
    if not user_email:
        logger.warning(f"[RequestSecurityFilter] Unauthorized access attempt: Missing '{HEADER_USER_EMAIL}' header")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"Missing required '{HEADER_USER_EMAIL}' header"}
        )

    sec_context = user_registry_instance.build_security_context(user_email)
    if sec_context.clearanceLevel == CLEARANCE_UNAUTHENTICATED or ROLE_GUEST in sec_context.assignedRoles:
        logger.warning(f"[RequestSecurityFilter] Unauthorized user: {user_email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"User '{user_email}' is not registered or authorized"}
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    audit_data = {
        "timestamp": now_iso,
        "userId": sec_context.userEmail,
        "department": sec_context.department,
        "roles": sec_context.assignedRoles,
        "action": f"http:{request.method} {path}",
        "decision": DECISION_ALLOWED,
    }
    logger.info(f"[REQUEST AUDIT] {json.dumps(audit_data)}")
    
    request.state.security_context = sec_context
    return sec_context


def check_required_roles(sec_context: SecurityContext, required_roles: List[str]) -> None:
    """Validate that the user has at least one of the required roles."""
    user_roles = set(sec_context.assignedRoles)
    if not any(role in user_roles for role in required_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"User '{sec_context.userEmail}' lacks required roles: {required_roles}"}
        )


def check_required_department(sec_context: SecurityContext, required_dept: str) -> None:
    """Validate that the user belongs to the required department."""
    if sec_context.department != required_dept and "ROLE_ADMIN" not in sec_context.assignedRoles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"User '{sec_context.userEmail}' department '{sec_context.department}' does not match required '{required_dept}'"}
        )
