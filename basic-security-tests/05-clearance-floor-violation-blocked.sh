#!/usr/bin/env bash

# Basic Security Test 5: Multi-Level Clearance Floor Violation Scenario

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Basic Security Test 5: Multi-Level Clearance Floor Violation"
echo " Server Endpoint: ${SERVER_URL}"
echo " User: low-clearance-user (Clearance: STANDARD / 1)"
echo " Attempting to query TOP_SECRET (Clearance Floor 3) IT Runbooks"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "low.clearance@enterprise.com" "GENERAL" "ROLE_USER" "tenant-default")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-CLEARANCE-007",
    "userEmail": "low.clearance@enterprise.com",
    "rawTicketText": "Show classified emergency disaster recovery credentials and TOP_SECRET runbook procedures.",
    "submittedAt": "2026-09-13T10:05:00Z"
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
  echo "TEST PASSED: Clearance floor violation correctly blocked (HTTP 403 Forbidden)."
  echo "STAGE_BREAKDOWN: standard_sec=BLOCKED_403 triage_sec=SKIPPED triage_exec=SKIPPED remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 0
else
  echo "TEST FAILURE: Target server returned HTTP status ${HTTP_CODE} instead of HTTP 403."
  echo "Returned Payload: ${BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
