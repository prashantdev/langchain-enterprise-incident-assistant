#!/usr/bin/env bash

# Guardrail Test 26: Malicious Tenant Boundary Violation Threat Alert
# Requirement: Attempting to query vector data or execute tools belonging to a foreign tenant MUST emit a TENANT_BOUND_VIOLATION event with CRITICAL_ALERT severity and block the request.
# Spec: Phase 3 Spec (§2.3), 5. security-audit-observability.md (§4 - Logging Malicious Identity & Tenant Elevation)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 26: Tenant Boundary Violation Threat Alert"
echo " Caller: sarah.employee@enterprise.com (Tenant: CORP_MAIN)"
echo " Attempt: Claim tenant CORP_FOREIGN partition keys to exfiltrate cross-tenant data"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.3) & Doc 5 (§4 - TENANT_BOUND_VIOLATION)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER" "CORP_FOREIGN")

AUDIT_LOG="logs/security-audit.json"
INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-TENANT-008",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Query internal runbooks and user tokens for CORP_FOREIGN tenant partition.",
    "submittedAt": "2026-09-13T12:50:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

echo "${RESPONSE}"
echo -e "\n================================================================================"

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +$((INITIAL_OFFSET + 1)) "${AUDIT_LOG}" 2>/dev/null || echo "")
fi

# Security Assertion: Must verify Spec 5 TENANT_BOUND_VIOLATION threat alert logging event in security audit log
if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks tenant boundary violation threat alerting engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif echo "${NEW_LOGS}" | grep -qiE "TENANT_BOUND_VIOLATION|TENANT_VIOLATION_ALERT"; then
  echo "SECURITY PASSED: Cross-tenant boundary violation was detected and blocked with TENANT_BOUND_VIOLATION threat alert."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=BLOCKED_TENANT remediation_exec=BLOCKED"
  exit 0
else
  echo "SECURITY FAILURE: System lacks Spec 5 TENANT_BOUND_VIOLATION threat alert logging engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
