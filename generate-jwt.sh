#!/usr/bin/env bash
# ==============================================================================
# Common JWT Generator Helper Script
# Generates signed JWT tokens with identity claims (sub, email, department, roles, tenantId)
# ==============================================================================

DEFAULT_SECRET="secret-key"
DEFAULT_TENANT_ID="tenant-default"
DEFAULT_DEPARTMENT="IT"
DEFAULT_ROLE="ROLE_USER"
DEFAULT_EMAIL="alex.devops@enterprise.com"

USER_EMAIL="${1:-$DEFAULT_EMAIL}"
DEPARTMENT="${2:-$DEFAULT_DEPARTMENT}"
USER_ROLE="${3:-$DEFAULT_ROLE}"
TENANT_ID="${4:-$DEFAULT_TENANT_ID}"
SECRET="${5:-$DEFAULT_SECRET}"

python3 - "$USER_EMAIL" "$DEPARTMENT" "$USER_ROLE" "$TENANT_ID" "$SECRET" << 'EOF'
import sys
import json
import base64
import hmac
import hashlib
import time

email = sys.argv[1]
department = sys.argv[2]
role = sys.argv[3]
tenant_id = sys.argv[4]
secret = sys.argv[5]

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": email,
    "email": email,
    "department": department,
    "roles": [role] if isinstance(role, str) else role,
    "tenantId": tenant_id,
    "iat": int(time.time())
}

header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
signature_b64 = base64url_encode(signature)

print(f"{header_b64}.{payload_b64}.{signature_b64}")
EOF
