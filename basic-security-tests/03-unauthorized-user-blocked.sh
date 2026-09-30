#!/usr/bin/env bash

# Test 3: Unauthorized User Request

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Synthetic Scenario 3: Unauthorized User Request"
echo " Server Endpoint: ${SERVER_URL}"
echo "================================================================================"

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "X-User-Email: unknown.attacker@external-domain.com" \
  -d '{
    "ticketId": "TCK-UNAUTH-003",
    "userEmail": "unknown.attacker@external-domain.com",
    "rawTicketText": "Please restart db-prod-01 database connection pool immediately.",
    "submittedAt": "2026-09-12T10:10:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "TEST FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  exit 1
fi

HTTP_CODE=$(echo "${RESPONSE}" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

echo "${RESPONSE}"
echo -e "\n================================================================================"

if [[ "${HTTP_CODE}" == "403" ]]; then
  echo "TEST PASSED: Unauthorized user correctly blocked (HTTP 403 Forbidden)."
  echo "STAGE_BREAKDOWN: standard_sec=BLOCKED_403 triage_sec=SKIPPED triage_exec=SKIPPED remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 0
else
  echo "TEST FAILURE: Target server returned HTTP status ${HTTP_CODE} instead of HTTP 403."
  echo "Returned Payload: ${BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
