#!/usr/bin/env bash

# Guardrail Test 05: Monotonic Classification Elevation Enforcement
# Requirement: Ingestion pipeline MUST enforce monotonic classification elevation (structural tags elevate section classification, but illegal de-escalation of parent document baseline is strictly rejected).
# Spec: 1. secure-ingestion-pipeline.md (§3 - Strict Monotonic Elevation)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 05: Monotonic Classification Elevation Enforcement"
echo " Verification: DocumentSecurityTransformer monotonic elevation enforcement"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 1 (§3 - Strict Monotonic Elevation)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-ING-010",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Ingest document with baseline RESTRICTED containing inline override tag <security:classification level=\"PUBLIC\"> to attempt de-escalation.",
    "submittedAt": "2026-09-13T12:35:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY=$(echo "${RESPONSE}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC=$(echo "${BODY}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks monotonic security classification elevation enforcement!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
elif echo "${BODY}" | grep -qiE "MONOTONIC_ELEVATION_ENFORCED|CLASSIFICATION_DE_ESCALATION_REJECTED" || [[ "${REMED_SEC}" == "PASSED" ]]; then
  echo "SECURITY PASSED: Monotonic classification elevation was properly enforced and de-escalation was rejected."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Ingestion pipeline allowed illegal de-escalation of document classification!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
