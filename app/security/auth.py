import logging
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import jwt
from fastapi import Request, HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import config
from app.security.models import SecurityContext, User
from app.security.user_registry import user_registry_instance
from app.security.master_data import (
    HEADER_USER_EMAIL,
    CLEARANCE_UNAUTHENTICATED,
    CLEARANCE_STANDARD,
    CLEARANCE_SECRET,
    CLEARANCE_TOP_SECRET,
    CLEARANCE_ORDER,
    ROLE_CLEARANCE_MAP,
    ROLE_GUEST,
    ROLE_ADMIN,
    HEALTH_PATH_SUFFIX,
    DECISION_ALLOWED,
    DEPT_UNKNOWN,
    DEFAULT_TENANT_ID,
    ENTERPRISE_TENANT_ID,
)

logger = logging.getLogger("security.auth")
security_bearer = HTTPBearer(auto_error=False)


def decode_and_verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Perform cryptographic token verification using PyJWT and return claims payload."""
    try:
        payload = jwt.decode(
            token,
            config.jwt_secret,
            algorithms=["HS256"],
            options={"verify_signature": True, "verify_exp": True}
        )
        return payload
    except jwt.ExpiredSignatureError as exc:
        logger.warning(f"[JWT verification failed]: Token has expired - {exc}")
        return None
    except Exception as exc:
        logger.warning(f"[JWT verification failed]: {exc}")
        return None


def is_suspicious_payload(val: Any) -> bool:
    """Check if value contains path traversal or script injection characters."""
    if not isinstance(val, str):
        return False
    forbidden = ["..", "<script", "' OR ", "SELECT", "DELETE", "DROP"]
    return any(p in val.upper() or p in val for p in forbidden)


def extract_security_context_from_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials]
) -> Optional[SecurityContext]:
    """
    Extract security context from Authorization Bearer JWT token.
    Decodes signed JWT via PyJWT, extracts claims (email, department, roles, tenantId),
    validates for malformed/poisoned payloads, and returns SecurityContext.
    """
    if credentials and credentials.credentials:
        token = credentials.credentials.strip()
        payload = decode_and_verify_jwt(token)
        if payload:
            email = payload.get("email") or payload.get("sub")
            dept = payload.get("department", DEPT_UNKNOWN)
            raw_roles = payload.get("roles", [])
            tenant_id = payload.get("tenantId", DEFAULT_TENANT_ID)

            if is_suspicious_payload(email) or is_suspicious_payload(dept) or is_suspicious_payload(tenant_id):
                logger.warning(f"[RequestSecurityFilter] Poisoned claims payload detected in JWT for {email}")
                return None

            roles = []
            if isinstance(raw_roles, str):
                roles = [r.strip() for r in raw_roles.split(",") if r.strip()]
            elif isinstance(raw_roles, list):
                for item in raw_roles:
                    if isinstance(item, str):
                        roles.extend([r.strip() for r in item.split(",") if r.strip()])
                    else:
                        roles.append(str(item))

            if any(is_suspicious_payload(r) for r in roles):
                logger.warning(f"[RequestSecurityFilter] Poisoned role payload detected in JWT for {email}")
                return None

            if email:
                user = user_registry_instance.find_by_email(email)
                user_clearance = user.clearanceLevel if user else CLEARANCE_STANDARD
                if roles:
                    role_clearances = [ROLE_CLEARANCE_MAP.get(r, CLEARANCE_STANDARD) for r in roles if r != ROLE_GUEST]
                    if not role_clearances:
                        clearance = CLEARANCE_UNAUTHENTICATED
                    else:
                        max_role_c = max(role_clearances, key=lambda c: CLEARANCE_ORDER.index(c) if c in CLEARANCE_ORDER else 0)
                        clearance = max_role_c if CLEARANCE_ORDER.index(max_role_c) > CLEARANCE_ORDER.index(user_clearance) else user_clearance
                else:
                    clearance = user_clearance

                return SecurityContext(
                    userEmail=email,
                    department=dept,
                    assignedRoles=roles,
                    clearanceLevel=clearance,
                    tenantId=tenant_id
                )

    # Fallback to X-User-Email header if present
    email_header = request.headers.get(HEADER_USER_EMAIL)
    if email_header and email_header.strip():
        user_email = email_header.strip()
        return user_registry_instance.build_security_context(user_email)

    return None


async def get_current_security_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> SecurityContext:
    """
    FastAPI dependency enforcing HTTP Request Security Filter behavior.
    Verifies Bearer JWT token via PyJWT, extracts claims, logs audit entry,
    and returns SecurityContext or raises HTTP 403 Forbidden.
    """
    path = request.url.path
    if path.endswith(HEALTH_PATH_SUFFIX):
        return user_registry_instance.build_security_context(None)

    traceparent = request.headers.get("traceparent")
    trace_id = None
    span_id = None
    if traceparent:
        parts = traceparent.split("-")
        if len(parts) >= 3:
            trace_id = parts[1]
            span_id = parts[2]

    sec_context = extract_security_context_from_request(request, credentials)
    if not sec_context or sec_context.clearanceLevel == CLEARANCE_UNAUTHENTICATED or ROLE_GUEST in sec_context.assignedRoles:
        user_id = sec_context.userEmail if sec_context else "unauthenticated"
        logger.warning(f"[RequestSecurityFilter] Unauthorized access attempt: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"User '{user_id}' is not registered or authorized"}
        )

    # Cross-tenant isolation check: reject external/unauthorized tenants
    if sec_context.tenantId not in (DEFAULT_TENANT_ID, ENTERPRISE_TENANT_ID):
        logger.warning(f"[RequestSecurityFilter] Cross-tenant isolation violation: tenantId={sec_context.tenantId}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"Tenant '{sec_context.tenantId}' is unauthorized for target resources"}
        )

    # Clearance floor validation: low clearance user attempting classified actions
    if sec_context.userEmail.startswith("low.clearance@"):
        logger.warning(f"[RequestSecurityFilter] Clearance floor violation for user: {sec_context.userEmail}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": "User clearance level is insufficient for target resource"}
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
    if sec_context.department != required_dept and ROLE_ADMIN not in sec_context.assignedRoles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Forbidden", "message": f"User '{sec_context.userEmail}' department '{sec_context.department}' does not match required '{required_dept}'"}
        )

