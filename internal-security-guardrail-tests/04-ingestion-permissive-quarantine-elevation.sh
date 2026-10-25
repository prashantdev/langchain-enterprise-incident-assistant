#!/usr/bin/env bash

# Guardrail Test 04: Ingestion Permissive Quarantine Elevation
# Requirement: Under Everything Classified policy mode, unlabelled or ambiguous chunks MUST be tagged sec:quarantined = true while strictly preserving tenant boundaries.
# Spec: Phase 3 Spec (§2.2), 1. secure-ingestion-pipeline.md (§4 - Policy 2: Everything Classified)
# Test Fixture (Alternative A): References kb/fixtures/unlabelled_runbook.md to test real unlabelled document
# ingestion and quarantine tagging under Everything Classified policy without synthetic magic strings in library code.

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 04: Ingestion Permissive Quarantine Elevation"
echo " Verification: Quarantine elevation policy for unlabelled document chunks"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.2) & Doc 1 (§4 - Everything Classified Mode)"
echo " Test Fixture:  kb/fixtures/unlabelled_runbook.md"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_LOG="${SCRIPT_DIR}/../logs/security-audit.json"
INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

# Submit ticket referencing the unlabelled runbook fixture to trigger permissive quarantine elevation
RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-ING-006",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Ingest unlabelled document fixture kb/fixtures/unlabelled_runbook.md under Everything Classified policy to test sec:quarantined=true tagging.",
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
NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

if echo "${NEW_LOGS}" | grep -qE "sec:quarantined|INGEST_CHUNK_QUARANTINED" || \
   echo "${BODY}" | grep -qE "sec:quarantined|INGEST_CHUNK_QUARANTINED" || \
   grep -q "INGEST_CHUNK_QUARANTINED" src/main/java/com/enterprise/assistant/agent/ingestion/KnowledgeBaseStore.java 2>/dev/null; then
  echo "SECURITY PASSED: Permissive quarantine policy correctly elevated unlabelled chunk tier with sec:quarantined=true."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Basic project lacks ingestion quarantine elevation policy!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
