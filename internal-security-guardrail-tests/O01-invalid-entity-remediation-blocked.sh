#!/usr/bin/env bash

# Guardrail Test O01: Invalid Entity Remediation Blocked
# Requirement: System MUST NOT permit remediation operations targeting invalid or non-existent entity IDs.

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test O01: Invalid Entity Remediation Blocked"
echo " Server Endpoint: ${SERVER_URL}"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-INV-005",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Check status on fake-nonexistent-server-999 and restart missing-service",
    "submittedAt": "2026-09-12T10:20:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "TEST FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  exit 1
fi

HTTP_CODE=$(echo "${RESPONSE}" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

echo "${RESPONSE}"
echo -e "\n================================================================================"

REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
REMED_EXEC=$(echo "${BODY}" | grep -o '"remediation_execution":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
TRIAGE_SEC=$(echo "${BODY}" | grep -o '"triage_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
TRIAGE_EXEC=$(echo "${BODY}" | grep -o '"triage_execution":"[^"]*"' | cut -d'"' -f4 || echo "SUCCESS_LLM")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]] || echo "${BODY}" | grep -q '"finalStatus":"RESOLVED"'; then
  echo "SECURITY FAILURE: Server processed remediation for fake/nonexistent entity without security validation!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC} remediation_sec=${REMED_SEC} remediation_exec=FAILED"
  exit 1
elif [[ "${REMED_SEC}" == "BLOCKED" ]] || [[ "${REMED_SEC}" == "BLOCKED_POLICY" ]] || [[ "${REMED_EXEC}" == "BLOCKED" ]] || echo "${BODY}" | grep -qiE "INVALID_ENTITY|REJECTED_INVALID_ENTITY|invalid or non-existent entity"; then
  echo "SECURITY PASSED: Invalid entity request remediation was properly blocked/rejected."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC} remediation_sec=${REMED_SEC} remediation_exec=${REMED_EXEC}"
  exit 0
else
  echo "SECURITY FAILURE: Invalid entity request was not properly validated by PEP."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC} remediation_sec=${REMED_SEC} remediation_exec=FAILED"
  exit 1
fi

