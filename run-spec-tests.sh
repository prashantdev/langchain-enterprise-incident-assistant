#!/usr/bin/env bash
# ==============================================================================
# Security Spec Guardrail Test Runner
#
# Runs internal security guardrail tests associated with library specifications
# 1 through N (where N is passed as a parameter from 1 to 5).
# Outputs test results and summary table using formatting matching run-security-suite.sh
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDRAIL_DIR="${SCRIPT_DIR}/internal-security-guardrail-tests"
CONFIG_FILE="${SCRIPT_DIR}/config.properties"

CONFIG_PORT=$(grep -E '^server\.port=' "${CONFIG_FILE}" 2>/dev/null | cut -d'=' -f2 | tr -d ' \r')
SERVER_URL="http://localhost:${CONFIG_PORT:-8080}/api/v1/tickets"
VERBOSE=false

usage() {
    cat << EOF
Usage: $(basename "$0") <spec_number_1_to_5> [OPTIONS]

Arguments:
  <spec_number_1_to_5>   Spec level from 1 to 5 to run tests for specs 1 through N

Options:
  -v, --verbose          Print detailed test output during execution
  -u, --url <SERVER_URL> Target API endpoint URL (default: ${SERVER_URL})
  -h, --help             Show this help message and exit

Examples:
  $(basename "$0") 4
  $(basename "$0") 4 -v
EOF
    exit 1
}

SPEC_NUM=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        [1-5])
            SPEC_NUM="$1"
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -u|--url)
            SERVER_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown argument: $1" >&2
            usage
            ;;
    esac
done

if [[ -z "${SPEC_NUM}" ]]; then
    echo "Error: Specification number parameter (1 to 5) is required." >&2
    usage
fi

# Define test sets mapping to library-specs 1 through 5
DOC1_NAME="1. secure-ingestion-pipeline.md"
DOC1_TESTS=(
    "T02-ingestion-envelope-validation-enforced.sh"
    "T04-ingestion-header-classification-elevation.sh"
    "T05-ingestion-strict-fail-closed-atomic-rollback.sh"
    "T06-ingestion-permissive-quarantine-elevation.sh"
    "T11-hmac-envelope-tamper-detection.sh"
)

DOC2_NAME="2. tool-execution-interceptor-&-parameter-constraints.md"
DOC2_TESTS=(
    "M01-unauthorized-tool-execution-blocked.sh"
    "M02-role-escalation-violation-blocked.sh"
    "M04-cel-parameter-department-mismatch-blocked.sh"
    "M05-dual-mode-hard-abort-enforced.sh"
    "M06-policy-brute-force-retry-loop-halted.sh"
    "O01-invalid-entity-remediation-blocked.sh"
    "O02-unauthorized-target-user-password-reset-blocked.sh"
    "O03-model-feedback-soft-refusal-returned.sh"
    "O04-cel-entity-attribute-hydration-resolved.sh"
)

DOC3_NAME="3. contextual-retrieval-filter-&-pruning-specification.md"
DOC3_TESTS=(
    "M03-rag-clearance-data-leakage-prevented.sh"
    "O07-rag-topk-predictive-oversampling-and-paging.sh"
)

DOC4_NAME="4. policy-decision-point-&-embedded-engine-specification.md"
DOC4_TESTS=(
    "O05-pdp-two-tier-cache-hit-performance.sh"
    "O06-remote-opa-pdp-circuit-breaker-fail-closed.sh"
    "O08-framework-starter-identity-propagation.sh"
)

DOC5_NAME="5. security-audit-observability.md"
DOC5_TESTS=(
    "T01-prompt-injection-blocked.sh"
    "T03-siem-audit-sanitization-enforced.sh"
    "T07-pii-regex-and-masked-annotation-scrubbing.sh"
    "T08-tenant-isolation-boundary-violation-alert.sh"
    "T09-opentelemetry-trace-span-correlation.sh"
)

# Arrays to collect test metrics
declare -a TEST_NAMES=()
declare -a TEST_SUITES=()
declare -a TEST_RESULTS=()
declare -a TEST_DURATIONS=()
declare -a TEST_REQ_SEC=()
declare -a TEST_TRIAGE_SEC=()
declare -a TEST_TRIAGE_EXEC=()
declare -a TEST_REMED_SEC=()
declare -a TEST_REMED_EXEC=()

PASSED_COUNT=0
FAILED_COUNT=0

run_test_file() {
    local suite_name="$1"
    local test_path="$2"
    local test_name
    test_name="$(basename "${test_path}")"

    local start_time
    start_time="$(date +%s%3N 2>/dev/null || date +%s)"

    local output_file
    output_file="$(mktemp)"

    local exit_code=0
    if bash "${test_path}" "${SERVER_URL}" > "${output_file}" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi

    local end_time
    end_time="$(date +%s%3N 2>/dev/null || date +%s)"
    local duration_ms=$(( end_time - start_time ))
    local duration_sec
    duration_sec=$(awk -v ms="${duration_ms}" 'BEGIN { printf "%.1fs", ms/1000 }')

    local req_sec="N/A"
    local triage_sec="N/A"
    local triage_exec="N/A"
    local remed_sec="N/A"
    local remed_exec="N/A"

    if grep -q "STAGE_BREAKDOWN:" "${output_file}"; then
        local breakdown_line
        breakdown_line=$(grep "STAGE_BREAKDOWN:" "${output_file}" | tail -n 1)
        req_sec=$(echo "${breakdown_line}" | sed -n 's/.*standard_sec=\([^ ]*\).*/\1/p')
        triage_sec=$(echo "${breakdown_line}" | sed -n 's/.*triage_sec=\([^ ]*\).*/\1/p')
        triage_exec=$(echo "${breakdown_line}" | sed -n 's/.*triage_exec=\([^ ]*\).*/\1/p')
        remed_sec=$(echo "${breakdown_line}" | sed -n 's/.*remediation_sec=\([^ ]*\).*/\1/p')
        remed_exec=$(echo "${breakdown_line}" | sed -n 's/.*remediation_exec=\([^ ]*\).*/\1/p')
    fi

    TEST_NAMES+=("${test_name}")
    TEST_SUITES+=("${suite_name}")
    TEST_DURATIONS+=("${duration_sec}")
    TEST_REQ_SEC+=("${req_sec:-N/A}")
    TEST_TRIAGE_SEC+=("${triage_sec:-N/A}")
    TEST_TRIAGE_EXEC+=("${triage_exec:-N/A}")
    TEST_REMED_SEC+=("${remed_sec:-N/A}")
    TEST_REMED_EXEC+=("${remed_exec:-N/A}")

    local status_pf
    if [[ ${exit_code} -eq 0 ]]; then
        status_pf=$(printf "\e[32mP\e[0m")
        TEST_RESULTS+=("PASSED")
        PASSED_COUNT=$(( PASSED_COUNT + 1 ))
    else
        status_pf=$(printf "\e[31mF\e[0m")
        TEST_RESULTS+=("FAILED")
        FAILED_COUNT=$(( FAILED_COUNT + 1 ))
    fi

    printf "[%-10s] %-48s %s (%s) [ReqSec: %s | TriSec: %s | TriExec: %s | RemSec: %s | RemExec: %s]\n" \
        "${suite_name}" "${test_name}" "${status_pf}" "${duration_sec}" \
        "${req_sec}" "${triage_sec}" "${triage_exec}" "${remed_sec}" "${remed_exec}"

    if [[ "${VERBOSE}" == true ]]; then
        echo "--------------------------------------------------------------------------------"
        cat "${output_file}"
        echo "--------------------------------------------------------------------------------"
    fi

    rm -f "${output_file}"
}

run_phase_tests() {
    local phase_num="$1"
    local doc_name="$2"
    shift 2
    local tests=("$@")

    echo "Running Phase ${phase_num} (${doc_name}) tests"
    echo "================================================================================"

    for test_file in "${tests[@]}"; do
        run_test_file "Spec-${phase_num}" "${GUARDRAIL_DIR}/${test_file}"
    done
    echo ""
}

echo "================================================================================"
echo " Starting Security Guardrail Test Suite (Specs 1..${SPEC_NUM})"
echo " Target URL   : ${SERVER_URL}"
echo " Start Time   : $(date)"
echo "================================================================================"
echo ""

GLOBAL_START_TIME="$(date +%s)"

if [[ ${SPEC_NUM} -ge 1 ]]; then
    run_phase_tests 1 "${DOC1_NAME}" "${DOC1_TESTS[@]}"
fi
if [[ ${SPEC_NUM} -ge 2 ]]; then
    run_phase_tests 2 "${DOC2_NAME}" "${DOC2_TESTS[@]}"
fi
if [[ ${SPEC_NUM} -ge 3 ]]; then
    run_phase_tests 3 "${DOC3_NAME}" "${DOC3_TESTS[@]}"
fi
if [[ ${SPEC_NUM} -ge 4 ]]; then
    run_phase_tests 4 "${DOC4_NAME}" "${DOC4_TESTS[@]}"
fi
if [[ ${SPEC_NUM} -ge 5 ]]; then
    run_phase_tests 5 "${DOC5_NAME}" "${DOC5_TESTS[@]}"
fi

GLOBAL_END_TIME="$(date +%s)"
TOTAL_DURATION=$(( GLOBAL_END_TIME - GLOBAL_START_TIME ))
TOTAL_TESTS=${#TEST_NAMES[@]}

echo "=========================================================================================================================="
echo " TEST EXECUTION SUMMARY REPORT"
echo "=========================================================================================================================="
printf "%-10s | %-42s | %-3s | %-12s | %-12s | %-15s | %-12s | %-15s | %-8s\n" \
    "SUITE" "TEST NAME" "RES" "REQUEST SEC" "TRIAGE SEC" "TRIAGE EXEC" "REMED SEC" "REMED EXEC" "DURATION"
echo "--------------------------------------------------------------------------------------------------------------------------"

for (( i=0; i<TOTAL_TESTS; i++ )); do
    local_suite="${TEST_SUITES[$i]}"
    local_name="${TEST_NAMES[$i]}"
    local_res="${TEST_RESULTS[$i]}"
    local_dur="${TEST_DURATIONS[$i]}"
    local_req_sec="${TEST_REQ_SEC[$i]}"
    local_triage_sec="${TEST_TRIAGE_SEC[$i]}"
    local_triage_exec="${TEST_TRIAGE_EXEC[$i]}"
    local_remed_sec="${TEST_REMED_SEC[$i]}"
    local_remed_exec="${TEST_REMED_EXEC[$i]}"

    if [[ "${local_res}" == "PASSED" ]]; then
        res_formatted=$(printf "\e[32mP\e[0m  ")
    else
        res_formatted=$(printf "\e[31mF\e[0m  ")
    fi

    printf "%-10s | %-42s | ${res_formatted} | %-12s | %-12s | %-15s | %-12s | %-15s | %-8s\n" \
        "${local_suite}" "${local_name}" "${local_req_sec}" "${local_triage_sec}" "${local_triage_exec}" "${local_remed_sec}" "${local_remed_exec}" "${local_dur}"
done

echo "=========================================================================================================================="
printf "Total Executed: %d | Passed: %d | Failed: %d | Duration: %ds\n" \
    "${TOTAL_TESTS}" "${PASSED_COUNT}" "${FAILED_COUNT}" "${TOTAL_DURATION}"
echo "=========================================================================================================================="

if [[ ${FAILED_COUNT} -gt 0 ]]; then
    exit 1
fi
