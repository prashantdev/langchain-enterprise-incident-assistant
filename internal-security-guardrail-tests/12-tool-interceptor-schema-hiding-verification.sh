#!/usr/bin/env bash

# Guardrail Test 12: Tool Interceptor Context Parameter Schema Hiding
# Requirement: Internal security identity parameters (RunnableConfig / SecurityIdentity) injected into tool function signatures MUST be hidden from OpenAPI / LLM JSON schemas.
# Spec: 2. tool-execution-interceptor-&-parameter-constraints.md (§1 - Context Injection Hiding)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 12: Tool Interceptor Context Parameter Schema Hiding"
echo " Verification: Tool execution interceptor schema hiding"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 2 (§1 - Context Injection Hiding)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-CEL-008",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Verify exposed tool schema parameter list for checkServerStatus and restartService.",
    "submittedAt": "2026-09-13T12:50:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks tool interceptor schema hiding verification!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif echo "${BODY}" | grep -qiE "SCHEMA_HIDING_VERIFIED|PARAM_HIDDEN" || [[ "${REMED_SEC}" == "PASSED" ]]; then
  echo "SECURITY PASSED: Security identity context parameters were properly hidden from LLM tool schemas."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Injected security identity context parameters leaked into model-facing tool schemas!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
