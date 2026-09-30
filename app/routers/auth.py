import logging
from fastapi import APIRouter, Depends, HTTPException, status
from app.security.models import LoginRequest, TokenResponse, SecurityContext
from app.security.user_registry import user_registry_instance
from app.security.auth import get_current_security_context

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

    return TokenResponse(
        access_token=user.email,
        token_type="bearer"
    )


@router.get("/me", response_model=SecurityContext)
def get_me(sec_context: SecurityContext = Depends(get_current_security_context)):
    return sec_context
