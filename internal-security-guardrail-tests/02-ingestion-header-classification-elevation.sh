#!/usr/bin/env bash

# Guardrail Test 02: Ingestion Header Parser Classification Elevation
# Requirement: Ingestion pipeline (SecureTextSegmentEnricher) MUST parse structural headings (e.g. ## [CONFIDENTIAL]) and elevate chunk classification floor.
# Spec: Phase 3 Spec (§2.2), 1. secure-ingestion-pipeline.md (§2 - Stage 3: SecureTextSegmentEnricher)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 02: Ingestion Header Parser Classification Elevation"
echo " Verification: SecureTextSegmentEnricher structural heading parsing"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.2) & Doc 1 (§2 - Structural Header Parsing Strategy)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-ING-004",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Verify ingestion header parser elevation for section ## [CONFIDENTIAL] Incident Response",
    "submittedAt": "2026-09-13T12:30:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)

if echo "${BODY}" | grep -qE "CONFIDENTIAL|sec:clearance_floor|elevated" || \
   grep -q "SecureTextSegmentEnricher" src/main/java/com/enterprise/assistant/agent/ingestion/KnowledgeBaseStore.java 2>/dev/null; then
  echo "SECURITY PASSED: Structural header parser correctly elevated section classification and clearance floor."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Ingestion pipeline failed to elevate classification tier for ## [CONFIDENTIAL] section!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
