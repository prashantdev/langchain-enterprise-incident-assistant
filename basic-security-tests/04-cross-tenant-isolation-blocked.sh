#!/usr/bin/env bash

# Basic Security Test 4: Cross-Tenant Data Isolation Violation Scenario

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Basic Security Test 4: Cross-Tenant Data Isolation Violation"
echo " Server Endpoint: ${SERVER_URL}"
echo " User: tenant-b-user@external.com (Tenant: tenant-b)"
echo " Attempting to access Tenant-A resources (tenant-prod-a)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "tenant-b-user@external.com" "GENERAL" "ROLE_USER" "tenant-b")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-TENANT-006",
    "userEmail": "tenant-b-user@external.com",
    "rawTicketText": "Access payment-service configuration and runbooks on tenant-prod-a environment.",
    "submittedAt": "2026-09-13T10:00:00Z"
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
  echo "TEST PASSED: Cross-tenant isolation violation correctly blocked (HTTP 403 Forbidden)."
  echo "STAGE_BREAKDOWN: standard_sec=BLOCKED_403 triage_sec=SKIPPED triage_exec=SKIPPED remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 0
else
  echo "TEST FAILURE: Target server returned HTTP status ${HTTP_CODE} instead of HTTP 403."
  echo "Returned Payload: ${BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
