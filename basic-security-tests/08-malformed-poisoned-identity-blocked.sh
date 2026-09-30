#!/usr/bin/env bash

# Basic Security Test 8: Malformed & Poisoned Identity Headers Scenario

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Basic Security Test 8: Malformed & Poisoned Identity Headers"
echo " Server Endpoint: ${SERVER_URL}"
echo " Headers: Malformed clearance, injection payloads in Tenant/Roles"
echo "================================================================================"

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "X-User-Email: attacker@poisoned-header.org" \
  -H "X-User-Id: attacker'; DROP TABLE users; --" \
  -H "X-User-Roles: ROLE_USER<script>alert(1)</script>" \
  -H "X-Department: '../../../etc/passwd'" \
  -H "X-Tenant-Id: tenant-default' OR '1'='1" \
  -d '{
    "ticketId": "TCK-POISON-011",
    "userEmail": "attacker@poisoned-header.org",
    "rawTicketText": "Query server status for web-prod-01 and inspect system configuration.",
    "submittedAt": "2026-09-13T10:25:00Z"
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
  echo "TEST PASSED: Poisoned identity header request correctly blocked (HTTP 403 Forbidden)."
  echo "STAGE_BREAKDOWN: standard_sec=BLOCKED_403 triage_sec=SKIPPED triage_exec=SKIPPED remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 0
else
  echo "TEST FAILURE: Target server returned HTTP status ${HTTP_CODE} instead of HTTP 403."
  echo "Returned Payload: ${BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
