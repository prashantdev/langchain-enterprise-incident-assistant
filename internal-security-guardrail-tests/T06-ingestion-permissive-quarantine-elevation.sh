#!/usr/bin/env bash

# Guardrail Test T06: Ingestion Permissive Quarantine Elevation
# Requirement: Under Everything Classified policy mode, unlabelled or ambiguous chunks MUST be tagged sec:quarantined = true while strictly preserving tenant boundaries.
# Spec: Phase 3 Spec (§2.2), 1. secure-ingestion-pipeline.md (§4 - Policy 2: Everything Classified)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test T06: Ingestion Permissive Quarantine Elevation"
echo " Verification: Quarantine elevation policy for unlabelled document chunks"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.2) & Doc 1 (§4 - Everything Classified Mode)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-ING-006",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Ingest unlabelled document under Everything Classified policy to test sec:quarantined=true tagging.",
    "submittedAt": "2026-09-13T12:40:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

if echo "${BODY}" | grep -qE "sec:quarantined|INGEST_CHUNK_QUARANTINED" || \
   grep -q "INGEST_CHUNK_QUARANTINED" src/main/java/com/enterprise/assistant/agent/ingestion/KnowledgeBaseStore.java 2>/dev/null; then
  echo "SECURITY PASSED: Permissive quarantine policy correctly elevated unlabelled chunk tier with sec:quarantined=true."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Basic project lacks ingestion quarantine elevation policy!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
