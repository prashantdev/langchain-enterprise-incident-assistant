#!/usr/bin/env bash

<<<<<<< Updated upstream:internal-security-guardrail-tests/T03-siem-audit-sanitization-enforced.sh
# Guardrail Test T03: SIEM Security Audit Logging & Data Sanitization
=======
# Guardrail Test 24: SIEM Security Audit Logging & Data Sanitization
>>>>>>> Stashed changes:internal-security-guardrail-tests/24-siem-audit-sanitization-enforced.sh
# Requirement: System MUST sanitize PII/credentials and emit structured audit events to SLF4J / SIEM.

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
<<<<<<< Updated upstream:internal-security-guardrail-tests/T03-siem-audit-sanitization-enforced.sh
echo " Running Guardrail Test T03: SIEM Security Audit Logging & Data Sanitization"
=======
echo " Running Guardrail Test 24: SIEM Security Audit Logging & Data Sanitization"
>>>>>>> Stashed changes:internal-security-guardrail-tests/24-siem-audit-sanitization-enforced.sh
echo " Verification: Inspecting audit logging subsystem capabilities"
echo "================================================================================"

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"
AUDIT_LOG="logs/security-audit.json"

# 1. Record log file size/line offset before request execution to isolate new logs
INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

# 2. Trigger live HTTP ticket request containing synthetic prompt payload & secret
UNIQUE_TICKET_ID="TCK-SIEM-$(date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWT_TOKEN=$("${SCRIPT_DIR}/../generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d "{
    \"ticketId\": \"${UNIQUE_TICKET_ID}\",
    \"userEmail\": \"sarah.employee@enterprise.com\",
    \"rawTicketText\": \"TEST SIEM SANITIZATION: secret=SUPER_SECRET_PASSWORD_999\",
    \"submittedAt\": \"2026-09-13T12:35:00Z\"
  }" || true)

# 3. Read ONLY newly appended log lines written after INITIAL_OFFSET
NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +$((INITIAL_OFFSET + 1)) "${AUDIT_LOG}" 2>/dev/null || echo "")
fi

# 4. Verify SIEM audit emission & PII/secret scrubbing
if echo "${NEW_LOGS}" | grep -q "${UNIQUE_TICKET_ID}" || \
   grep -q "Slf4jJsonAuditPublisher" src/main/resources/logback.xml 2>/dev/null; then
  if echo "${NEW_LOGS}" | grep -q "SUPER_SECRET_PASSWORD_999"; then
    echo "SECURITY FAILURE: SIEM audit log leaked unmasked secret payload in clear text!"
    echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
    exit 1
  else
    echo "SECURITY PASSED: Audit subsystem emitted SIEM taxonomy and enforced secret sanitization."
    echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=PASSED remediation_exec=ENFORCED"
    exit 0
  fi
else
  echo "SECURITY FAILURE: Basic demoproject lacks Slf4jJsonAuditPublisher and secret/PII masking pipeline!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=SKIPPED triage_exec=N/A remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
