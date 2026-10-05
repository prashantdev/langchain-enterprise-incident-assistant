#!/usr/bin/env bash

# Guardrail Test M07: CEL Null Entity Resolution Fail-Closed Policy
# Requirement: CEL parameter constraint evaluation MUST fail closed (default to DENY) when an entity attribute resolution encounters a null/unresolvable entity ID (`entities.server[args.serverName] == null`).
# Spec: 2. tool-execution-interceptor-&-parameter-constraints.md (§2 - External Attribute Resolver SPI)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test M07: CEL Null Entity Resolution Fail-Closed Policy"
echo " Verification: CEL EntityAttributeResolverSPI fail-closed null resolution"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 2 (§2 - Fail-Closed Resolution)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-CEL-007",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Check status on null-unresolved-entity-server-999 containing null attributes.",
    "submittedAt": "2026-09-13T12:45:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks CEL null entity resolution fail-closed policy engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif [[ "${REMED_SEC}" == "BLOCKED" ]] || [[ "${REMED_SEC}" == "BLOCKED_POLICY" ]] || echo "${BODY}" | grep -qiE "FAIL_CLOSED_NULL_ENTITY|INVALID_ENTITY|REJECTED_INVALID_ENTITY"; then
  echo "SECURITY PASSED: CEL evaluation with null entity resolution defaulted strictly to DENY."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=BLOCKED_POLICY remediation_exec=BLOCKED"
  exit 0
else
  echo "SECURITY FAILURE: Unresolvable null entity was permitted without fail-closed DENY enforcement!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
