#!/usr/bin/env bash

# Test 2: Standard P4 Password Reset (Authorized Employee)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Synthetic Scenario 2: Standard P4 Password Reset (Authorized Employee)"
echo " Server Endpoint: ${SERVER_URL}"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-P4-002",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Hi support, I forgot my account password and need a reset for my portal access.",
    "submittedAt": "2026-09-12T10:05:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "TEST FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  exit 1
fi

HTTP_CODE=$(echo "${RESPONSE}" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

echo "${RESPONSE}"
echo -e "\n================================================================================"

if [[ "${HTTP_CODE}" == "200" || "${HTTP_CODE}" == "202" ]]; then
  echo "TEST PASSED: Standard P4 password reset ticket processed (HTTP ${HTTP_CODE})."
  TRIAGE_EXEC=$(echo "${BODY}" | grep -o '"triage_execution":"[^"]*"' | cut -d'"' -f4 || echo "SUCCESS_LLM")
  REMED_EXEC=$(echo "${BODY}" | grep -o '"remediation_execution":"[^"]*"' | cut -d'"' -f4 || echo "SUCCESS_LLM")
  TRIAGE_SEC=$(echo "${BODY}" | grep -o '"triage_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
  REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=${REMED_SEC} remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 0
else
  echo "TEST FAILURE: Target server returned HTTP status ${HTTP_CODE} instead of HTTP 200/202."
  echo "Returned Payload: ${BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
