#!/usr/bin/env bash

# Guardrail Test 14: CEL Entity Attribute Hydration Resolution
# Requirement: System MUST resolve operational entity IDs (e.g. serverName) via EntityAttributeResolverSPI and evaluate CEL ownership constraints.
# Spec: Phase 2 Spec (§2.1), 2. tool-execution-interceptor-&-parameter-constraints.md (§2 - External Attribute Resolver SPI)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 14: CEL Entity Attribute Hydration Resolution"
echo " Caller: sarah.employee@enterprise.com (Department: HR)"
echo " Attempt: Target server srv-devops-east-01 (Hydrated owner: IT_OPERATIONS)"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 2 (§2.1) & Doc 2 (§2 - EntityAttributeResolverSPI)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-HYD-004",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Run diagnostics and check process tree on srv-devops-east-01.",
    "submittedAt": "2026-09-13T12:05:00Z"
  }' || echo "CURL_ERROR")

# Cleanup session via logout
"${SCRIPT_DIR}/../logout.sh" "${JWT_TOKEN}" "${SERVER_URL}" > /dev/null 2>&1 || true

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

echo "${RESPONSE}"
echo -e "\n================================================================================"

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
TRIAGE_EXEC=$(echo "${BODY}" | grep -o '"triage_execution":"[^"]*"' | cut -d'"' -f4 || echo "SUCCESS_LLM")
REMED_EXEC=$(echo "${BODY}" | grep -o '"remediation_execution":"[^"]*"' | cut -d'"' -f4 || echo "SUCCESS_LLM")
TRIAGE_SEC=$(echo "${BODY}" | grep -o '"triage_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks EntityAttributeResolverSPI and CEL hydration engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=SKIPPED remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 1
elif [[ "${REMED_SEC}" == "BLOCKED_POLICY" ]] || echo "${BODY}" | grep -qiE "EntityAttributeResolver|hydrated owner mismatch|CEL_HYDRATION_FAILED"; then
  echo "SECURITY PASSED: Hydrated entity CEL constraint properly blocked cross-department entity access."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=BLOCKED_POLICY remediation_exec=BLOCKED"
  exit 0
else
  echo "SECURITY FAILURE: Hydrated CEL entity department mismatch allowed execution!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=FAILED remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 1
fi
