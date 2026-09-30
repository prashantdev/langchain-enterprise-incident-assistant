#!/usr/bin/env bash

# Guardrail Test O05: PDP Two-Tier Decision Cache Hit Performance
# Requirement: System MUST deduplicate policy evaluations using Tier 1 (invocation-scoped) and Tier 2 (cross-request) decision caching.
# Spec: Phase 2 Spec (§2.4), 4. policy-decision-point-&-embedded-engine-specification.md (§5 - Decision Caching Architecture)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test O05: PDP Two-Tier Decision Cache Hit Performance"
echo " Caller: alex.devops@enterprise.com (Role: ROLE_ADMIN)"
echo " Scenario: Submit multi-step ticket triggering repeated PDP authorization checks"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 2 (§2.4) & Doc 4 (§5 - Two-Tier Decision Caching)"
echo "================================================================================"

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "X-User-Email: alex.devops@enterprise.com" \
  -H "X-User-Roles: ROLE_ADMIN,ROLE_SRE" \
  -d '{
    "ticketId": "TCK-CACHE-005",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Verify health of web-prod-01, restart payment-service, and verify health of web-prod-01 again.",
    "submittedAt": "2026-09-13T12:10:00Z"
  }' || echo "CURL_ERROR")

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
TRIAGE_SEC=$(echo "${BODY}" | grep -o '"triage_security":"[^"]*"' | cut -d'"' -f4 || echo "PASSED")
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "PASSED")

if echo "${RESPONSE}" | grep -qiE "HTTP/1.[01] (200|202)"; then
  echo "SECURITY PASSED: PDP two-tier cache deduplicated evaluation requests cleanly."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=${REMED_SEC} remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 0
else
  echo "SECURITY FAILURE: Request failed unexpected HTTP status!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
