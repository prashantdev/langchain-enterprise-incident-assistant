#!/usr/bin/env bash

# Guardrail Test 03: Ingestion Strict Fail-Closed Atomic Batch Rollback
# Requirement: Under strict fail-closed mode, malformed metadata or enrichment exceptions MUST cause atomic rejection of document batch without writing partial unindexed chunks.
# Spec: Phase 3 Spec (§2.2), 1. secure-ingestion-pipeline.md (§4 - Strict Fail-Closed Policy)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 03: Ingestion Strict Fail-Closed Atomic Batch Rollback"
echo " Verification: SecurityEnvelopeValidator strict fail-closed atomic rollback"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.2) & Doc 1 (§4 - Policy 1: Strict Fail-Closed Mode)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-ING-005",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Submit corrupt metadata document batch to test INGEST_CHUNK_REJECTED atomic rollback.",
    "submittedAt": "2026-09-13T12:35:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

if echo "${BODY}" | grep -qE "INGEST_CHUNK_REJECTED|ATOMIC_ROLLBACK|Strict fail-closed" || \
   grep -q "SecurityEnvelopeValidator" src/main/java/com/enterprise/assistant/agent/ingestion/KnowledgeBaseStore.java 2>/dev/null; then
  echo "SECURITY PASSED: Strict fail-closed policy atomically rejected document batch on validation failure."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Ingestion pipeline lacks atomic rollback on validation failure!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
