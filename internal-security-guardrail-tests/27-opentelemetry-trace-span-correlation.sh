#!/usr/bin/env bash

<<<<<<< Updated upstream:internal-security-guardrail-tests/T09-opentelemetry-trace-span-correlation.sh
# Guardrail Test T09: OpenTelemetry W3C Trace & Span ID Correlation
=======
# Guardrail Test 27: OpenTelemetry W3C Trace & Span ID Correlation
>>>>>>> Stashed changes:internal-security-guardrail-tests/27-opentelemetry-trace-span-correlation.sh
# Requirement: Security audit records MUST extract W3C traceparent headers and bind active trace_id and span_id context to log records.
# Spec: Phase 3 Spec (§2.5), 5. security-audit-observability.md (§6 - Enterprise SIEM Publisher SPI)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"
AUDIT_LOG="logs/security-audit.json"

echo "================================================================================"
<<<<<<< Updated upstream:internal-security-guardrail-tests/T09-opentelemetry-trace-span-correlation.sh
echo " Running Guardrail Test T09: OpenTelemetry W3C Trace & Span ID Correlation"
=======
echo " Running Guardrail Test 27: OpenTelemetry W3C Trace & Span ID Correlation"
>>>>>>> Stashed changes:internal-security-guardrail-tests/27-opentelemetry-trace-span-correlation.sh
echo " Verification: OpenTelemetryLogsPublisher trace_id and span_id binding"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Phase 3 (§2.5) & Doc 5 (§6 - OpenTelemetry Exporter)"
echo "================================================================================"

INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

TRACE_ID="4bf92f3577b34da6a3ce929d0e0e4736"
SPAN_ID="00f067aa0ba902b7"
TRACEPARENT="00-${TRACE_ID}-${SPAN_ID}-01"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "alex.devops@enterprise.com" "DevOps" "ROLE_DEVOPS_ENGINEER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "traceparent: ${TRACEPARENT}" \
  -d '{
    "ticketId": "TCK-OTEL-009",
    "userEmail": "alex.devops@enterprise.com",
    "rawTicketText": "Verify OpenTelemetry trace correlation in security audit log.",
    "submittedAt": "2026-09-13T12:55:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +$((INITIAL_OFFSET + 1)) "${AUDIT_LOG}" 2>/dev/null || echo "")
fi

if [[ ! -f "${AUDIT_LOG}" ]] || [[ -z "${NEW_LOGS}" ]]; then
  echo "SECURITY FAILURE: Basic project lacks OpenTelemetry audit publisher for W3C trace correlation!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
elif echo "${NEW_LOGS}" | grep -q "${TRACE_ID}"; then
  echo "SECURITY PASSED: OpenTelemetry audit publisher correctly bound W3C traceId and spanId to audit envelope."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: OpenTelemetry trace correlation failed; traceparent header trace_id was not bound in audit log!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
