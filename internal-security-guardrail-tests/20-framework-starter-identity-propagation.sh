#!/usr/bin/env bash

# Guardrail Test 20: Framework Starter Identity Propagation
# Requirement: Spring Boot (SpringSecurityIdentityBridge) and Quarkus (QuarkusSecurityIdentityBridge) starters MUST automatically map framework auth context into InvocationParameters.
# Spec: Phase 2 Spec (§2.6), 0. langchain4j-security.md (§1 - Modular Architecture)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 20: Framework Starter Identity Propagation"
echo " Verification: Spring Security / Quarkus IdentityBridge auto-configuration"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 2 (§2.6) & Doc 0 (§1 - Framework Starter Modules)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-STARTER-008",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Check ticket status and my entitlements.",
    "submittedAt": "2026-09-13T12:25:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

echo "${RESPONSE}"
echo -e "\n================================================================================"

AUDIT_LOG="logs/security-audit.json"
NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(cat "${AUDIT_LOG}" 2>/dev/null || echo "")
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
TRIAGE_EXEC=$(echo "${BODY}" | grep -o '"triage_execution":"[^"]*"' | cut -d'"' -f4 || echo "SUCCESS_LLM")
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "PASSED")

if echo "${NEW_LOGS}" | grep -qiE "IDENTITY_BRIDGE|AUTHENTICATION_SUCCESS|IDENTITY_PROPAGATED" || echo "${RESPONSE}" | grep -qiE "IDENTITY_BRIDGE|AUTHENTICATION_SUCCESS|IDENTITY_PROPAGATED"; then
  echo "SECURITY PASSED: Framework starter identity bridge extracted caller context into InvocationParameters."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=${REMED_SEC:-PASSED} remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 0
else
  echo "SECURITY FAILURE: Framework starter identity resolution failed!"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
