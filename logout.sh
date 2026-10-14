#!/usr/bin/env bash
# ==============================================================================
# Common Logout Helper Script
# Calls application logout endpoint to invalidate identity and evict PDP decision cache
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PORT=$(grep -E '^server\.port=' "${SCRIPT_DIR}/config.properties" 2>/dev/null | cut -d'=' -f2 | tr -d ' \r')
DEFAULT_PORT="${CONFIG_PORT:-8080}"
DEFAULT_SERVER_URL="http://localhost:${DEFAULT_PORT}"

JWT_TOKEN="${1:-}"
SERVER_URL="${2:-$DEFAULT_SERVER_URL}"

# If first arg looks like a URL instead of JWT token, swap them
if [[ "${JWT_TOKEN}" =~ ^https?:// ]]; then
    TEMP="${JWT_TOKEN}"
    JWT_TOKEN="${SERVER_URL}"
    SERVER_URL="${TEMP}"
fi

# Clean trailing ticket path if passed
SERVER_BASE="${SERVER_URL%/api/v1/tickets}"
SERVER_BASE="${SERVER_BASE%/api/tickets}"
LOGOUT_URL="${SERVER_BASE}/api/auth/logout"

if [[ -z "${JWT_TOKEN}" ]]; then
    # Generate default guest/cleanup token
    JWT_TOKEN=$("${SCRIPT_DIR}/generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_ADMIN")
fi

curl -s -X POST "${LOGOUT_URL}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JWT_TOKEN}" || true
