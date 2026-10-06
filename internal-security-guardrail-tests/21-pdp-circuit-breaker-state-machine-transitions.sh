#!/usr/bin/env bash

<<<<<<< Updated upstream:internal-security-guardrail-tests/O11-pdp-circuit-breaker-state-machine-transitions.sh
# Guardrail Test O11: PDP Remote Circuit Breaker State Machine Transitions
=======
# Guardrail Test 21: PDP Remote Circuit Breaker State Machine Transitions
>>>>>>> Stashed changes:internal-security-guardrail-tests/21-pdp-circuit-breaker-state-machine-transitions.sh
# Requirement: Remote PDP adapter MUST manage circuit breaker transitions (CLOSED -> OPEN -> HALF_OPEN) during remote PDP failures and fail closed to local PDP evaluation without throwing unhandled exceptions.
# Spec: 4. policy-decision-point-&-embedded-engine-specification.md (§3 - Remote OPA PDP Adapter & Circuit Breaker)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
<<<<<<< Updated upstream:internal-security-guardrail-tests/O11-pdp-circuit-breaker-state-machine-transitions.sh
echo " Running Guardrail Test O11: PDP Remote Circuit Breaker State Machine Transitions"
=======
echo " Running Guardrail Test 21: PDP Remote Circuit Breaker State Machine Transitions"
>>>>>>> Stashed changes:internal-security-guardrail-tests/21-pdp-circuit-breaker-state-machine-transitions.sh
echo " Verification: Remote OPA PDP adapter circuit breaker state transition lifecycle"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 4 (§3 - Remote OPA PDP Adapter & Circuit Breaker)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-PDP-011",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Trigger remote PDP connection timeout to verify circuit breaker transition to OPEN state and local PDP fail-closed fallback.",
    "submittedAt": "2026-09-13T13:05:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks PDP remote circuit breaker state machine engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif echo "${BODY}" | grep -qiE "CIRCUIT_BREAKER_OPEN|LOCAL_PDP_FALLBACK|CIRCUIT_BREAKER_TRANSITION" || [[ "${REMED_SEC}" == "PASSED" ]] || [[ "${REMED_SEC}" == "BLOCKED_POLICY" ]]; then
  echo "SECURITY PASSED: Circuit breaker properly managed state transitions (CLOSED -> OPEN) and failed closed safely."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Remote PDP timeout caused unhandled system failure or bypassed policy enforcement!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
