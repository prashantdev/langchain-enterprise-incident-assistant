#!/usr/bin/env bash

# Guardrail Test 31: Sliding-Window Cross-Turn Abuse Throttling & Custom Window Lifecycle
# Requirement: Repeated denied tool executions by a single subject across multiple conversation turns within a sliding window MUST trigger the sliding-window abuse tracker, emit a `POLICY_BRUTE_FORCE_SCANNING` critical SIEM alert upon reaching the threshold (`max_denials`), halt execution across turns, and properly roll off (prune) once the sliding window expires. Custom sliding windows and denial caps must also be supported and enforced.
# Spec: 2. tool-execution-interceptor-&-parameter-constraints.md (§3 - Anti-Loop Mitigation & Escalation Boundary) & 5. security-audit-observability.md (§4 - Threat Classification & Security Event Taxonomy)

SERVER_URL="${1:-http://localhost:8080/api/v1/tickets}"

echo "================================================================================"
echo " Running Guardrail Test 31: Sliding-Window Cross-Turn Abuse Throttling"
echo " Verification: Multi-turn sliding-window abuse detection and custom window pruning"
echo " Server Endpoint: ${SERVER_URL}"
echo " Specification: Doc 2 (§3 - Escalation Boundary) & Doc 5 (§4 - Security Event Taxonomy)"
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

# Authenticate caller as scanner user (clearance 0, lacks permission for production servers)
JWT_TOKEN=$("${PROJECT_DIR}/generate-jwt.sh" "scanner.attacker@enterprise.com" "IT_SUPPORT" "ROLE_USER")

# ==============================================================================
# Phase 1: Cross-Turn Sliding-Window Denial Accumulation via HTTP API
# ==============================================================================

# Turn 1: Single unauthorized check on web-prod-01 (Denial 1 of 3)
RESPONSE_TURN1=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-SLIDE-001",
    "userEmail": "scanner.attacker@enterprise.com",
    "rawTicketText": "Check server operational health for web-prod-01",
    "submittedAt": "2026-09-13T14:00:00Z"
  }' || echo "CURL_ERROR")

if [[ "${RESPONSE_TURN1}" == "CURL_ERROR" ]] || [[ -z "${RESPONSE_TURN1}" ]]; then
  echo "SECURITY FAILURE: Could not connect to target server at ${SERVER_URL} (Server Unreachable)."
  echo "STAGE_BREAKDOWN: standard_sec=FAILED triage_sec=FAILED triage_exec=FAILED remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

BODY_TURN1=$(echo "${RESPONSE_TURN1}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC_TURN1=$(echo "${BODY_TURN1}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "SKIPPED")

# Check for unhardened master branch
if [[ "${REMED_SEC_TURN1}" == "SKIPPED" ]] || [[ "${REMED_SEC_TURN1}" == "SKIPPED (NO_POLICY_ENGINE)" ]] || [[ "${REMED_SEC_TURN1}" == "N/A" ]]; then
  echo "SECURITY FAILURE: Basic project lacks SIEM policy brute-force threat scanning engine!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=SKIPPED remediation_exec=SKIPPED"
  exit 1
fi

LOGS_TURN1=""
if [[ -f "${AUDIT_LOG}" ]]; then
  LOGS_TURN1=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

# Turn 1 should NOT trigger brute force scanning alert yet
if echo "${LOGS_TURN1}" | grep -qi "POLICY_BRUTE_FORCE_SCANNING"; then
  echo "SECURITY FAILURE: POLICY_BRUTE_FORCE_SCANNING prematurely emitted on turn 1!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

# Turn 2: Second unauthorized check on hr-app-01 (Denial 2 of 3)
RESPONSE_TURN2=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-SLIDE-002",
    "userEmail": "scanner.attacker@enterprise.com",
    "rawTicketText": "Check server operational health for hr-app-01",
    "submittedAt": "2026-09-13T14:00:02Z"
  }' || echo "CURL_ERROR")

LOGS_TURN2=""
if [[ -f "${AUDIT_LOG}" ]]; then
  LOGS_TURN2=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

if echo "${LOGS_TURN2}" | grep -qi "POLICY_BRUTE_FORCE_SCANNING"; then
  echo "SECURITY FAILURE: POLICY_BRUTE_FORCE_SCANNING prematurely emitted on turn 2!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

# Turn 3: Third unauthorized check on db-prod-01 (Denial 3 of 3 - Threshold Reached)
RESPONSE_TURN3=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-SLIDE-003",
    "userEmail": "scanner.attacker@enterprise.com",
    "rawTicketText": "Check server operational health for db-prod-01",
    "submittedAt": "2026-09-13T14:00:04Z"
  }' || echo "CURL_ERROR")

BODY_TURN3=$(echo "${RESPONSE_TURN3}" | sed -n '/^\r\?$/,$p' | tail -n +2)

LOGS_TURN3=""
if [[ -f "${AUDIT_LOG}" ]]; then
  LOGS_TURN3=$(tail -n +"$((INITIAL_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true)
fi

# Turn 3 MUST emit POLICY_BRUTE_FORCE_SCANNING alert
if ! echo "${LOGS_TURN3}" | grep -qiE "POLICY_BRUTE_FORCE_SCANNING|BRUTE_FORCE_ALERT_EMITTED"; then
  echo "SECURITY FAILURE: Cross-turn repeated denials did not emit POLICY_BRUTE_FORCE_SCANNING alert on turn 3!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

# Turn 4: Subsequent request while within sliding window MUST be throttled
RESPONSE_TURN4=$(curl -s -i -X POST "${SERVER_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "ticketId": "TEST-SLIDE-004",
    "userEmail": "scanner.attacker@enterprise.com",
    "rawTicketText": "Check server operational health for finance-db-01",
    "submittedAt": "2026-09-13T14:00:06Z"
  }' || echo "CURL_ERROR")

BODY_TURN4=$(echo "${RESPONSE_TURN4}" | sed -n '/^\r\?$/,$p' | tail -n +2)
REMED_SEC_TURN4=$(echo "${BODY_TURN4}" | grep -o '"remediation_security":"[^"]*"' | cut -d'"' -f4 || echo "")

if ! echo "${BODY_TURN4}" | grep -qiE "POLICY_BRUTE_FORCE_SCANNING|BLOCKED_BY_POLICY" && [[ "${REMED_SEC_TURN4}" != "BLOCKED_POLICY" ]]; then
  echo "SECURITY FAILURE: Throttled user request on turn 4 was not halted by sliding window abuse guard!"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

# Cleanup session via logout
"${PROJECT_DIR}/logout.sh" "${JWT_TOKEN}" "${SERVER_URL}" > /dev/null 2>&1 || true

# ==============================================================================
# Phase 2: Custom Sliding Windows & Window Expiration Lifecycle Verification
# ==============================================================================
CUSTOM_WINDOW_VERIFY=$(PYTHONPATH="${PROJECT_DIR}" "${VENV_PYTHON}" - << 'PYEOF'
import sys
import time
from app.config import config
from app.agents.remediation_agent import remediation_agent_instance
from langchain_security_extension.security_adapter_langchain.violation_handler import (
    AbuseThrottleTracker,
    RetryBudgetTracker,
    ToolViolationHandler,
)

# 1. Verify RemediationAgent violation_handler binds application config
abuse_tracker = remediation_agent_instance.violation_handler.abuse_tracker
retry_tracker = remediation_agent_instance.violation_handler.retry_tracker

if abuse_tracker.window_seconds != config.abuse_window_seconds:
    print(f"FAILED_CONFIG_WINDOW_MISMATCH: {abuse_tracker.window_seconds} != {config.abuse_window_seconds}")
    sys.exit(1)

if abuse_tracker.max_denials != config.abuse_max_denials:
    print(f"FAILED_CONFIG_DENIALS_MISMATCH: {abuse_tracker.max_denials} != {config.abuse_max_denials}")
    sys.exit(1)

if retry_tracker.max_feedback_violations != config.retry_max_violations:
    print(f"FAILED_CONFIG_RETRY_MISMATCH: {retry_tracker.max_feedback_violations} != {config.retry_max_violations}")
    sys.exit(1)

# 2. Verify Custom Sliding Window pruning & expiration behavior
custom_window = 1.0  # 1.0 second sliding window
custom_cap = 2      # Threshold: 2 denials
test_subject = "custom.scanner@enterprise.com"

tracker = AbuseThrottleTracker.create(window_seconds=custom_window, max_denials=custom_cap)

# Attempt 1: Denial at t0 -> Should NOT throttle (1 < 2)
t0 = time.time()
throttled_1 = tracker.record_denial(test_subject, t0)
if throttled_1 or tracker.is_throttled(test_subject, t0):
    print("FAILED_PREMATURE_CUSTOM_THROTTLE")
    sys.exit(1)

# Attempt 2: Denial at t0 + 0.1s -> MUST throttle (2 >= 2)
t1 = t0 + 0.1
throttled_2 = tracker.record_denial(test_subject, t1)
if not throttled_2 or not tracker.is_throttled(test_subject, t1):
    print("FAILED_CUSTOM_THRESHOLD_NOT_TRIGGERED")
    sys.exit(1)

# Wait for custom sliding window to expire (> 1.0s)
time.sleep(1.2)

# Attempt 3: Denial at t0 + 1.3s -> Window must prune past attempts, count should reset to 1 (< 2)
t2 = time.time()
throttled_3 = tracker.record_denial(test_subject, t2)
if throttled_3 or tracker.is_throttled(test_subject, t2):
    print("FAILED_CUSTOM_WINDOW_EXPIRATION_ROLLOVER")
    sys.exit(1)

print("VERIFY_CUSTOM_WINDOW_SUCCESS")
sys.exit(0)
PYEOF
)

if [[ "${CUSTOM_WINDOW_VERIFY}" != *"VERIFY_CUSTOM_WINDOW_SUCCESS"* ]]; then
  echo "SECURITY FAILURE: Custom sliding window and config binding verification failed: ${CUSTOM_WINDOW_VERIFY}"
  echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=FAILED remediation_exec=FAILED"
  exit 1
fi

echo "SECURITY PASSED: Sliding-window cross-turn abuse throttling and custom sliding window successfully enforced."
echo "STAGE_BREAKDOWN: standard_sec=PASSED triage_sec=PASSED triage_exec=SUCCESS_LLM remediation_sec=PASSED remediation_exec=ENFORCED"
exit 0
