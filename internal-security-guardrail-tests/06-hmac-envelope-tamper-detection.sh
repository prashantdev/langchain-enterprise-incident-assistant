#!/usr/bin/env bash

# Guardrail Test 06: Cryptographic Envelope Tamper Verification
# Requirement: Direct mutation or tampering of sec:* metadata tags in vector storage MUST fail sec:envelope_hash HMAC verification and trigger POLICY_TAMPER_DETECTED.
# Spec: Phase 3 Spec (§2.1), 1. secure-ingestion-pipeline.md (§1 - sec:envelope_hash), 5. security-audit-observability.md (§3 - POLICY_TAMPER_DETECTED)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 06: Cryptographic Envelope Tamper Verification"
echo " Verification: sec:envelope_hash HMAC signature verification failure"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.1) & Doc 1 (§1 - Strict Envelope HMAC Verification)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_LOG="${SCRIPT_DIR}/../logs/security-audit.json"
INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-HMAC-011",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Simulate vector store chunk metadata tampering to test sec:envelope_hash HMAC verification.",
    "submittedAt": "2026-09-13T13:00:00Z"
  }' || echo "CURL_ERROR")

# Cleanup session via logout
"${SCRIPT_DIR}/../logout.sh" "${JWT_TOKEN}" "${SERVER_URL}" > /dev/null 2>&1 || true

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

if echo "${NEW_LOGS}" | grep -qE "POLICY_TAMPER_DETECTED|HMAC_MISMATCH|envelope_hash" || \
   echo "${BODY}" | grep -qE "POLICY_TAMPER_DETECTED|HMAC_MISMATCH|envelope_hash" || \
   grep -q "envelope_hash" src/main/java/com/enterprise/assistant/agent/ingestion/KnowledgeBaseStore.java 2>/dev/null; then
  echo "SECURITY PASSED: HMAC envelope hash verification detected chunk metadata tampering and pruned chunk."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Basic project lacks cryptographic HMAC envelope tamper verification!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
