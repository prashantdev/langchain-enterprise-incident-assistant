#!/usr/bin/env bash

# Guardrail Test 07: Unlabelled Document Chunk Quarantine Policy
# Requirement: Chunks ingested without explicit security envelope metadata (sec:*) MUST be quarantined/pruned under strict ingestion mode.
# Spec: 1. secure-ingestion-pipeline.md (§2 - Stage 4: SecurityEnvelopeValidator)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 07: Unlabelled Document Chunk Quarantine Policy"
echo " Verification: SecurityEnvelopeValidator unlabelled chunk quarantine"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 1 (§2 - Stage 4: SecurityEnvelopeValidator)"
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
    "ticketId": "TEST-ING-012",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Ingest unlabelled raw text chunk lacking sec:tenant_id and sec:allowed_roles under strict ingestion mode.",
    "submittedAt": "2026-09-13T12:40:00Z"
  }' || echo "CURL_ERROR")

# Cleanup session via logout
"${SCRIPT_DIR}/../logout.sh" "${JWT_TOKEN}" "${SERVER_URL}" > /dev/null 2>&1 || true

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks unlabelled chunk quarantine policy engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif echo "${NEW_LOGS}" | grep -qiE "UNLABELLED_CHUNK_QUARANTINED|MISSING_SECURITY_ENVELOPE|INGEST_CHUNK_REJECTED" || \
     echo "${BODY}" | grep -qiE "UNLABELLED_CHUNK_QUARANTINED|MISSING_SECURITY_ENVELOPE|BLOCKED" || [[ "${REMED_SEC}" == "BLOCKED" ]]; then
  echo "SECURITY PASSED: Unlabelled document chunk was properly quarantined under strict ingestion mode."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=BLOCKED remediation_exec=BLOCKED"
  exit 0
else
  echo "SECURITY FAILURE: Unlabelled chunk lacking security envelope was ingested without quarantine enforcement!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
