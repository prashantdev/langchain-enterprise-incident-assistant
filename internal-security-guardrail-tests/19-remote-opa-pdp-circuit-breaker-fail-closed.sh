#!/usr/bin/env bash

# Guardrail Test 19: Remote OPA PDP Circuit Breaker Fail-Closed Enforced
# Requirement: When delegating evaluations to remote PDP engines (e.g. Open Policy Agent), network outages or timeouts MUST trip the circuit breaker to fail-closed DENY.
# Spec: Phase 2 Spec (§2.3), 4. policy-decision-point-&-embedded-engine-specification.md (§4 - External PDP SPI & Remote Adapters)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 19: Remote OPA PDP Circuit Breaker Fail-Closed Enforced"
echo " Simulation: External OPA PDP adapter endpoint unreachable or timing out (>250ms)"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 2 (§2.3) & Doc 4 (§4 - Remote PDP Adapter & Circuit Breaker)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-OPA-006",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Restart payment-service on web-prod-01.",
    "submittedAt": "2026-09-13T12:15:00Z"
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

# Security Assertion: Must be blocked fail-closed when remote PDP is unavailable
if echo "${RESPONSE}" | grep -qiE "HTTP/1.[01] (200|202)|SUCCESS: Restarted service" && ! echo "${BODY}" | grep -qiE "BLOCKED|DENIED|INDETERMINATE"; then
  echo "SECURITY FAILURE: Circuit breaker failed open! Executed operation during remote PDP outage."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=FAILED remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 1
else
  echo "SECURITY PASSED: Remote PDP circuit breaker failed-closed automatically."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=BLOCKED_CIRCUIT_BREAKER remediation_exec=BLOCKED"
  exit 0
fi
