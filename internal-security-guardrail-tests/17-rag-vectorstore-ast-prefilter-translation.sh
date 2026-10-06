#!/usr/bin/env bash

# Guardrail Test 17: VectorStore AST Pre-Filter Translation
# Requirement: Contextual retrieval MUST derive and translate caller SecurityIdentity into native VectorStore pre-filters ($and conjunction of sec:tenant_id, sec:clearance_floor, sec:allowed_roles) prior to vector similarity query.
# Spec: 3. contextual-retrieval-filter-&-pruning-specification.md (§2 - Security Filter AST Translation Engine)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 17: VectorStore AST Pre-Filter Translation"
echo " Verification: SecureRetriever VectorStore AST pre-filter generation"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 3 (§2 - Security Filter AST Translation Engine)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-RAG-009",
    "userEmail": "sarah.employee@enterprise.com",
    "rawTicketText": "Query vector store runbooks for payment service recovery instructions.",
    "submittedAt": "2026-09-13T12:55:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks vector store AST pre-filter translation engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif echo "${BODY}" | grep -qiE "VECTOR_AST_PREFILTER_APPLIED|AST_TRANSLATION_SUCCESS" || [[ "${REMED_SEC}" == "PASSED" ]]; then
  echo "SECURITY PASSED: Caller SecurityIdentity was properly translated into native VectorStore AST pre-filters."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Vector retriever executed un-filtered similarity query without native AST pre-filtering!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
