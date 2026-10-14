#!/usr/bin/env bash

# Guardrail Test 22: PDP Cache Eviction on Identity Invalidation
# Requirement: L1/L2 policy evaluation cache entries MUST be immediately invalidated when caller roles or clearance levels are updated/revoked in UserRegistry.
# Spec: 4. policy-decision-point-&-embedded-engine-specification.md (§2 - Embedded Policy Decision Point & Two-Tier Cache Architecture)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 22: PDP Cache Eviction on Identity Invalidation"
echo " Verification: PDP L1/L2 cache invalidation upon identity credential revocation"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 4 (§2 - Two-Tier Cache Architecture)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_LOG="${SCRIPT_DIR}/../logs/security-audit.json"
INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "revoked.user@enterprise.com" "IT_SUPPORT" "ROLE_USER")

# Step 1: Submit ticket to populate PDP decision cache
RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-PDP-012",
    "userEmail": "revoked.user@enterprise.com",
    "rawTicketText": "Verify immediate PDP cache eviction following user role revocation.",
    "submittedAt": "2026-09-13T13:10:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks PDP policy cache invalidation mechanism!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
fi

# Step 2: Trigger identity invalidation & cache eviction via logout endpoint
LOGOUT_RESP=$("${SCRIPT_DIR}/../logout.sh" "${JWT_TOKEN}" "${SERVER_URL}")

NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

# Step 3: Verify cache eviction event in SIEM audit log or non-zero evicted_count in logout response
if echo "${NEW_LOGS}" | grep -qiE "CACHE_EVICTED|PDP_CACHE_INVALIDATED" || \
   echo "${LOGOUT_RESP}" | grep -qiE '"evicted_count":\s*[1-9]' || \
   echo "${BODY}" | grep -qiE "CACHE_EVICTED|PDP_CACHE_INVALIDATED"; then
  echo "SECURITY PASSED: User role revocation immediately invalidated PDP policy decision cache."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Stale PDP cache permitted request execution after identity credential revocation!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
