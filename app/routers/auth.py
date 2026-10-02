import logging
import time
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from app.config import config
from app.security.models import LoginRequest, TokenResponse, SecurityContext
from app.security.user_registry import user_registry_instance
from app.security.auth import get_current_security_context
from app.security.master_data import DEFAULT_TENANT_ID

JWT_EXPIRATION_SECONDS = 6 * 3600  # 6 hours

logger = logging.getLogger("router.auth")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
def login(login_req: LoginRequest):
    user = user_registry_instance.find_by_email(login_req.email)
    if user is None or user.password != login_req.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Unauthorized", "message": "Invalid email or password"}
        )

    now = int(time.time())
    payload = {
        "sub": user.email,
        "email": user.email,
        "department": user.department,
        "roles": user.roles,
        "tenantId": DEFAULT_TENANT_ID,
        "iat": now,
        "exp": now + JWT_EXPIRATION_SECONDS,
    }
    token = jwt.encode(payload, config.jwt_secret, algorithm="HS256")
    return TokenResponse(
        access_token=token,
        token_type="bearer"
    )


@router.get("/me", response_model=SecurityContext)
def get_me(sec_context: SecurityContext = Depends(get_current_security_context)):
    return sec_context
