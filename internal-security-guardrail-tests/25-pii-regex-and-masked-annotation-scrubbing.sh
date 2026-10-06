#!/usr/bin/env bash

# Guardrail Test 25: In-Flight PII & Sensitive Payload Sanitization
# Requirement: System MUST automatically scrub @Masked parameters and regex credential matches (AWS keys, Bearer tokens, DB URIs) replacing secrets with [REDACTED].
# Spec: Phase 3 Spec (§2.4), 5. security-audit-observability.md (§5 - In-Flight PII & Sensitive Payload Sanitization)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"
AUDIT_LOG="logs/security-audit.json"

echo "================================================================================"
echo " Running Guardrail Test 25: In-Flight PII & Sensitive Payload Sanitization"
echo " Verification: Inspecting audit pipeline credential regex & @Masked scrubbing"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.4) & Doc 5 (§5 - Sanitization Pipeline)"
echo "================================================================================"

INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

UNIQUE_ID="TCK-PII-$(date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d "{
    \"ticketId\": \"${UNIQUE_ID}\",
    \"userEmail\": \"sarah.employee@enterprise.com\",
    \"rawTicketText\": \"TEST PII MASKING: aws_key=AKIAIOSFODNN7EXAMPLE bearer=Bearer_secretToken_12345\",
    \"submittedAt\": \"2026-09-13T12:45:00Z\"
  }" || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +$((INITIAL_OFFSET + 1)) "${AUDIT_LOG}" 2>/dev/null || echo "")
fi

if [[ ! -f "${AUDIT_LOG}" ]] || [[ -z "${NEW_LOGS}" ]]; then
  echo "SECURITY FAILURE: Basic project lacks security audit logging pipeline for PII scrubbing!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
elif echo "${NEW_LOGS}" | grep -qE "AKIAIOSFODNN7EXAMPLE|Bearer_secretToken_12345"; then
  echo "SECURITY FAILURE: Audit pipeline leaked unmasked AWS API key or Bearer token!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
elif echo "${NEW_LOGS}" | grep -q "\[REDACTED\]"; then
  echo "SECURITY PASSED: Sensitive payload sanitization engine scrubbed credentials to [REDACTED]."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Sensitive payload sanitization engine did not perform credential scrubbing!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
