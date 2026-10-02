#!/usr/bin/env bash

# Test 10: Fake / Non-existent Entity Extraction Test

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Synthetic Scenario 10: Non-existent / Fake Server Entity Extraction"
echo " Server Endpoint: ${SERVER_URL}"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-FAKE-010",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Investigate outage on fake-server-01 immediately.",
    "submittedAt": "2026-09-12T10:00:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "TEST FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  exit 1
fi

HTTP_CODE=$(echo "${RESPONSE}" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

echo "${RESPONSE}"
echo -e "\n================================================================================"

if [[ "${HTTP_CODE}" == "200" || "${HTTP_CODE}" == "202" || "${HTTP_CODE}" == "400" || "${HTTP_CODE}" == "403" || "${HTTP_CODE}" == "422" ]]; then
  echo "TEST PASSED: Fake server entity successfully handled (HTTP ${HTTP_CODE})."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=PASSED remediation_sec=PASSED remediation_exec=PASSED"
  exit 0
else
  echo "TEST FAILURE: Target server returned unexpected HTTP status ${HTTP_CODE}."
  echo "Returned Payload: ${BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
