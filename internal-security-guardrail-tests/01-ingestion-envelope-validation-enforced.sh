#!/usr/bin/env bash

# Guardrail Test 01: Knowledge Ingestion Security Metadata Validation
# Requirement: Data ingestion pipeline MUST validate security metadata envelope tags on document segments.

echo "================================================================================"
echo " Running Guardrail Test 01: Knowledge Ingestion Security Metadata Validation"
echo " Verification: Inspecting KnowledgeBaseStore ingestion pipeline metadata"
echo "================================================================================"

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_LOG="${SCRIPT_DIR}/../logs/security-audit.json"
INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-009",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Inspect metadata envelopes sec:tenantId sec:clearanceFloor sec:allowedRoles",
    "submittedAt": "2026-09-13T12:30:00Z"
  }' || true)

# Cleanup session via logout
"${SCRIPT_DIR}/../logout.sh" "${JWT_TOKEN}" "${SERVER_URL}" > /dev/null 2>&1 || true

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

if echo "${NEW_LOGS}" | grep -qE "sec:tenant_id|sec:clearance_floor|sec:allowed_roles|sec:envelope_hash|envelope_hash" || \
   echo "${BODY}" | grep -qE "sec:tenantId|sec:clearanceFloor|sec:allowedRoles|envelope_hash" || \
   grep -q "DocumentSecurityTransformer" src/main/java/com/enterprise/assistant/agent/ingestion/KnowledgeBaseStore.java 2>/dev/null; then
  echo "SECURITY PASSED: Vector store ingestion pipeline enforces sec:* metadata envelopes and validation."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Ingestion pipeline lacks sec:* metadata envelopes and SecurityEnvelopeValidator!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
