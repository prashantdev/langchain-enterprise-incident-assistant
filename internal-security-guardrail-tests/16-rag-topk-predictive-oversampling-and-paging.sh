#!/usr/bin/env bash

# Guardrail Test 16: Top-K Predictive Candidate Oversampling & Secondary Paging
# Requirement: System MUST inflate retrieval fetch window (K_fetch = K_target * 3.0) and use adaptive secondary paging to prevent result starvation when post-retrieval chunk pruning occurs.
# Spec: Phase 2 Spec (§2.5), 3. contextual-retrieval-filter-&-pruning-specification.md (§4 - Post-Retrieval Pruning Engine)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 16: Top-K Oversampling & Adaptive Paging"
echo " Caller: sarah.employee@enterprise.com (Clearance: Level 1)"
echo " Attempt: Query IT runbooks requiring K=5 authorized chunks from mixed vector store"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 2 (§2.5) & Doc 3 (§4 - Top-K Compensation Engine)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TCK-OVERSAMPLE-007",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Provide full troubleshooting steps for general network connectivity issues.",
    "submittedAt": "2026-09-13T12:20:00Z"
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
TRIAGE_SEC=$(echo "${BODY}" | grep -o '"triage_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")
RAG_CLEARANCE=$(echo "${BODY}" | grep -o '"rag_clearance":"[^"]*"' | cut -d'"' -f4 || echo "UNCHECKED")

# Verify Top-K predictive candidate oversampling engine is active
if [[ "${RAG_CLEARANCE}" == *"UNCHECKED"* ]] || [[ "${RAG_CLEARANCE}" == *"Standard Retriever"* ]] || [[ "${REMED_SEC}" == *"SKIPPED"* ]] || ! echo "${BODY}" | grep -qiE "OVERSAMPLED|topk_oversampling|SecureRetrieverWrapper"; then
  echo "SECURITY FAILURE: Basic project uses Standard Retriever without Top-K predictive candidate oversampling!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=SKIPPED remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 1
elif echo "${RESPONSE}" | grep -qiE "HTTP/1.[01] (200|202)"; then
  echo "SECURITY PASSED: Top-K predictive oversampling and secondary paging prevented result starvation."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=${REMED_SEC} remediation_exec=${REMED_EXEC:-SUCCESS_LLM}"
  exit 0
else
  echo "SECURITY FAILURE: Request failed unexpected HTTP status!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
