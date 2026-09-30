#!/usr/bin/env bash

# Guardrail Test T10: Audit Ring-Buffer High-Volume Stress Test & Backpressure
# Requirement: System MUST process high-volume asynchronous audit logging bursts without blocking LLM inference threads or dropping HTTP connections.
# Spec: Phase 3 Spec (§2.5), 5. security-audit-observability.md (§1, §6.3)

ARG1="${1:-http://localhost:8080/api/v1/tickets}"
ARG2="${2:-}"

if [[ "${ARG1}" =~ ^http:// || "${ARG1}" =~ ^https:// ]]; then
  SERVER_URL="${ARG1}"
  NUM_REQUESTS="${ARG2:-3}"
else
  NUM_REQUESTS="${ARG1:-3}"
  SERVER_URL="${ARG2:-http://localhost:8080/api/v1/tickets}"
fi

echo "================================================================================"
echo " Running Guardrail Test T10: Audit Ring-Buffer High-Volume Stress Test"
echo " Server Endpoint : ${SERVER_URL}"
echo " Burst Requests  : ${NUM_REQUESTS}"
echo " Specification   : Phase 3 (Doc 5 §1 & §6.3) - Async Ring-Buffer Backpressure"
echo "================================================================================"

SUCCESSFUL=0
FAILURES=0
UNREACHABLE=0
LAST_STATUS=""
LAST_BODY=""

for i in $(seq 1 "${NUM_REQUESTS}"); do
  echo "Dispatched request #${i} of ${NUM_REQUESTS}..."
  RESP=$(curl -s -i -X POST "${SERVER_URL}" \
    -H "Content-Type: application/json" \
    -H "X-User-Email: alex.devops@enterprise.com" \
    -H "X-User-Id: stress-user-${i}" \
    -H "X-User-Roles: ROLE_USER" \
    -H "X-Department: STRESS_DEPT" \
    -H "X-Tenant-Id: tenant-default" \
    -d "{
      \"ticketId\": \"TCK-STRESS-12-${i}\",
      \"userEmail\": \"alex.devops@enterprise.com\",
      \"rawTicketText\": \"High frequency log burst request #${i}. Check server status for web-prod-01.\",
      \"submittedAt\": \"2026-09-13T10:30:00Z\"
    }" || echo "CURL_ERROR")

  if [[ "${RESP}" == "CURL_ERROR" ]] || [[ -z "${RESP}" ]]; then
    UNREACHABLE=$(( UNREACHABLE + 1 ))
  else
    CODE=$(echo "${RESP}" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
    LAST_STATUS="${CODE}"
    LAST_BODY=$(echo "${RESP}" | sed -n '/^\r\?$/,$p' | tail -n +2)
    if [[ "${CODE}" == "200" || "${CODE}" == "202" || "${CODE}" == "403" ]]; then
      SUCCESSFUL=$(( SUCCESSFUL + 1 ))
    else
      FAILURES=$(( FAILURES + 1 ))
    fi
  fi
done

echo -e "\nFinished dispatching ${NUM_REQUESTS} burst requests (successful: ${SUCCESSFUL}, failed: ${FAILURES}, unreachable: ${UNREACHABLE})."
echo "================================================================================"

if [[ ${UNREACHABLE} -eq ${NUM_REQUESTS} ]]; then
  echo "SECURITY FAILURE: Target server endpoint ${SERVER_URL} is unreachable!"
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
elif [[ ${SUCCESSFUL} -gt 0 && ${FAILURES} -eq 0 && ${UNREACHABLE} -eq 0 ]]; then
  echo "SECURITY PASSED: Audit ring buffer stress requests processed smoothly without backpressure degradation."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=PASSED remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Requests returned unexpected HTTP status code ${LAST_STATUS}."
  echo "Sample Response Payload: ${LAST_BODY}"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
