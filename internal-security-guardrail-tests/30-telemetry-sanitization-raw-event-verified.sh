#!/usr/bin/env bash

# Guardrail Test 30: Telemetry Sanitization Raw Event Dictionary Inspection
# Requirement: Emitted audit events from AuditManager MUST sanitize sensitive parameters so that plaintext secrets/PII never leak into raw event dictionaries (event.to_dict() / JSON logs).
# Spec: 5. security-audit-observability.md (§5 - In-Flight PII & Sensitive Payload Sanitization Pipeline)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 30: Telemetry Sanitization Raw Event Dictionary Test"
echo " Caller: sarah.employee@enterprise.com (Role: ROLE_USER, Dept: HR)"
echo " Verification: Inspect emitted AuditManager raw event dicts for zero secret leakage"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 5 (§5 - In-Flight PII & Sensitive Payload Sanitization)"
echo "================================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="$(cd "${PROJECT_DIR}/.." && pwd)"
AUDIT_LOG="${PROJECT_DIR}/logs/security-audit.json"

VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"
if [[ ! -x "${VENV_PYTHON}" ]]; then
  VENV_PYTHON="python3"
fi

INITIAL_OFFSET=0
if [[ -f "${AUDIT_LOG}" ]]; then
  INITIAL_OFFSET=$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)
fi

UNIQUE_TICKET_ID="TCK-TELEMETRY-SAN-$(date +%s)"
JWT_TOKEN=$("${PROJECT_DIR}/generate-jwt.sh" "sarah.employee@enterprise.com" "HR" "ROLE_USER")

RAW_SECRET_PASS="PlaintextPass_987654!"
RAW_API_KEY="sk_live_SensitiveApiKey_554433"
RAW_AWS_KEY="AKIAIOSFODNN7EXAMPLE"
RAW_BEARER="Bearer_SecretJwtToken_998877"
RAW_DB_PASS="DbMasterSecret_112233"
RAW_SSN="123-45-6789"

RESPONSE=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d "{
    \"ticketId\": \"${UNIQUE_TICKET_ID}\",
    \"userEmail\": \"sarah.employee@enterprise.com\",
    \"rawTicketText\": \"Reset credentials on hr-app-01: password=${RAW_SECRET_PASS} api_key=${RAW_API_KEY} aws_key=${RAW_AWS_KEY} bearer=${RAW_BEARER} db_uri=postgres://admin:${RAW_DB_PASS}@db-prod-01:5432/prod ssn=${RAW_SSN}\",
    \"submittedAt\": \"2026-10-13T08:35:00Z\"
  }" || echo "CURL_ERROR")

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

NEW_LOGS=""
if [[ -f "${AUDIT_LOG}" ]]; then
  NEW_LOGS=$(tail -n +$((INITIAL_OFFSET + 1)) "${AUDIT_LOG}" 2>/dev/null || echo "")
fi

# 1. Verify server is running with AuditManager pipeline enabled (fails on unhardened master branch)
if [[ "${REMED_SEC}" == "SKIPPED" ]] || [[ "${REMED_SEC}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || \
   [[ -z "${NEW_LOGS}" ]] || ! echo "${NEW_LOGS}" | grep -q "${UNIQUE_TICKET_ID}"; then
  echo "SECURITY FAILURE: Server lacks AuditManager telemetry emission and sanitization pipeline!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

# 2. Assert sensitive parameters never leaked into emitted JSON log dictionaries
if echo "${NEW_LOGS}" | grep -qE "${RAW_SECRET_PASS}|${RAW_API_KEY}|${RAW_AWS_KEY}|${RAW_BEARER}|${RAW_DB_PASS}|${RAW_SSN}"; then
  echo "SECURITY FAILURE: Sensitive parameters leaked into raw AuditManager JSON event logs!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

# 3. Inspect emitted AuditEvent.to_dict() dictionaries directly from AuditManager
SANITIZATION_VERIFY=$(PYTHONPATH="${PROJECT_DIR}" "${VENV_PYTHON}" - "${UNIQUE_TICKET_ID}" "${RAW_SECRET_PASS}" "${RAW_API_KEY}" "${RAW_AWS_KEY}" "${RAW_BEARER}" "${RAW_DB_PASS}" "${RAW_SSN}" << 'PYEOF'
import json
import sys
from app.security.security_integration import get_pdp_engine
from security_core.audit import AuditEvent, InMemoryAuditLogger

ticket_id, raw_pass, raw_api_key, raw_aws_key, raw_bearer, raw_db_pass, raw_ssn = sys.argv[1:8]
forbidden_secrets = [raw_pass, raw_api_key, raw_aws_key, raw_bearer, raw_db_pass, raw_ssn]

pdp_engine = get_pdp_engine()
audit_manager = getattr(pdp_engine, "audit_manager", None)
if audit_manager is None:
    print("FAILED_NO_AUDIT_MANAGER")
    sys.exit(1)

in_mem_pub = None
for pub in audit_manager.publishers:
    if isinstance(pub, InMemoryAuditLogger):
        in_mem_pub = pub
        break

if in_mem_pub is None:
    print("FAILED_NO_IN_MEMORY_LOGGER")
    sys.exit(1)

# Emit a structured tool execution audit event with both sensitive keys and embedded secret strings
sensitive_event = AuditEvent.create(
    subject_id="sarah.employee@enterprise.com",
    tenant_id="tenant-default",
    action="tool:execute",
    resource="reset_user_password",
    decision="PERMIT",
    diagnostic_reason=f"Executing tool with password={raw_pass} and bearer={raw_bearer}",
    severity="INFORMATIONAL",
    metadata={
        "ticketId": ticket_id,
        "password": raw_pass,
        "secret": raw_pass,
        "api_key": raw_api_key,
        "aws_key": raw_aws_key,
        "bearer_token": raw_bearer,
        "ssn": raw_ssn,
        "nested_params": {
            "private_key": raw_api_key,
            "db_connection": f"postgres://admin:{raw_db_pass}@db-prod-01:5432/prod",
            " inline_credentials": f"aws_key={raw_aws_key} password={raw_pass} ssn={raw_ssn}",
        },
        "arg_list": [
            f"token={raw_bearer}",
            {"credential": raw_pass},
        ],
    },
    enforcement_point="TOOL_INTERCEPTOR",
    reason_code="TOOL_EXECUTE_PERMITTED",
)

audit_manager.record_event(sensitive_event)

emitted_events = [
    e for e in in_mem_pub.get_events()
    if isinstance(getattr(e, "payload_snapshot", None), dict)
    and e.payload_snapshot.get("ticketId") == ticket_id
]

if not emitted_events:
    print("FAILED_NO_EMITTED_EVENTS_FOUND")
    sys.exit(1)

for ev in emitted_events:
    raw_dict = ev.to_dict()
    serialized = json.dumps(raw_dict)
    for secret_val in forbidden_secrets:
        if secret_val in serialized:
            print(f"FAILED_SECRET_LEAKED_IN_DICT: {secret_val}")
            sys.exit(1)

    snap = raw_dict.get("payload_snapshot", {})
    if snap.get("password") != "[REDACTED]" or snap.get("api_key") != "[REDACTED]" or snap.get("ssn") != "[REDACTED]":
        print(f"FAILED_KEY_REDACTION: {snap}")
        sys.exit(1)
    if "[REDACTED]" not in snap.get("nested_params", {}).get("db_connection", ""):
        print(f"FAILED_NESTED_REDACTION: {snap}")
        sys.exit(1)

print(f"SANITIZATION_VERIFIED: inspected_events={len(emitted_events)}")
PYEOF
)

VERIFY_EXIT=$?
echo "${SANITIZATION_VERIFY}"

if [[ ${VERIFY_EXIT} -eq 0 ]] && echo "${SANITIZATION_VERIFY}" | grep -q "SANITIZATION_VERIFIED"; then
  echo "SECURITY PASSED: Emitted AuditManager events sanitized all sensitive parameters; zero secrets leaked into raw event dictionaries."
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=PASSED remediation_exec=ENFORCED"
  exit 0
else
  echo "SECURITY FAILURE: Sensitive parameters leaked or were not properly scrubbed in AuditManager raw event dictionaries!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=${TRIAGE_SEC} triage_exec=${TRIAGE_EXEC:-SUCCESS_LLM} remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi
