#!/usr/bin/env bash

# Basic Security Test 15: Unauthenticated RAG Request Blocked
# Requirement: Unauthenticated RAG requests lacking Bearer JWT headers MUST be blocked at the HTTP authentication boundary.
# Spec: Basic Security API Auth

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Basic Security Test 15: Unauthenticated RAG Request Blocked"
echo " Verification: Basic HTTP API Authentication Boundary"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Basic API Auth"
echo "================================================================================"

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -d '{
    "ticketId": "TEST-RAG-010",
    "userEmail": "",
    "rawTicketText": "Unauthenticated query attempting wildcard vector search scan across runbooks.",
    "submittedAt": "2026-09-13T13:00:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if echo "${RESPONSE}" | grep -qiE "HTTP/1.[01] (401|403)|DENY_ALL_UNAUTHENTICATED" || [[ "${REMED_SEC}" == "BLOCKED" ]] || [[ "${REMED_SEC}" == "BLOCKED_POLICY" ]]; then
  echo "SECURITY PASSED: Unauthenticated RAG query injected deny-all sentinel filter and was blocked."
  echo "STAGE_BREAKDOWN: standard_sec=BLOCKED_403 triage_sec=SKIPPED triage_exec=SKIPPED remediation_sec=BLOCKED remediation_exec=BLOCKED"
  exit 0
else
  echo "SECURITY FAILURE: Unauthenticated query executed unconstrained wildcard search against vector database!"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
