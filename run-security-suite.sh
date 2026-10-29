#!/usr/bin/env bash
# ==============================================================================
# Security Test Suite Meta-Runner
#
# Runs scripts in basic-security-tests/ and internal-security-guardrail-tests/,
# collates execution outcomes, and prints a consolidated summary report.
# ==============================================================================

set -euo pipefail

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PORT=$(grep -E '^server\.port=' "${SCRIPT_DIR}/config.properties" 2>/dev/null | cut -d'=' -f2 | tr -d ' \r')
CONFIG_LLM_URL=$(grep -E '^model1\.baseUrl=' "${SCRIPT_DIR}/config.properties" 2>/dev/null | cut -d'=' -f2- | tr -d ' \r')
SERVER_URL="http://localhost:${CONFIG_PORT}/api/v1/tickets"
SELECTED_SUITE="all"
VERBOSE=false

BASIC_DIR="${SCRIPT_DIR}/basic-security-tests"
GUARDRAIL_DIR="${SCRIPT_DIR}/internal-security-guardrail-tests"

# Print usage helper
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -s, --suite <basic|guardrail|all>  Select test suite to run (default: all)
  --basic                            Run only basic security tests
  --guardrail                        Run only internal guardrail tests
  --all                              Run all test suites
  -u, --url <SERVER_URL>             Target API endpoint URL (default: ${SERVER_URL})
  -v, --verbose                      Print detailed test output during execution
  -h, --help                         Show this help message and exit

Examples:
  $(basename "$0") --suite guardrail
  $(basename "$0") --suite basic --url http://localhost:8080/api/v1/tickets
  $(basename "$0") --all
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            SELECTED_SUITE="all"
            shift
            ;;
        --basic)
            SELECTED_SUITE="basic"
            shift
            ;;
        --guardrail)
            SELECTED_SUITE="guardrail"
            shift
            ;;
        -s|--suite)
            SELECTED_SUITE="$2"
            shift 2
            ;;
        -u|--url)
            SERVER_URL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
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

# Validate suite argument
case "${SELECTED_SUITE}" in
    basic|guardrail|all) ;;
    *)
        echo "Error: Invalid suite '${SELECTED_SUITE}'. Options are: basic, guardrail, all." >&2
        exit 1
        ;;
esac

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

run_suite_directory() {
    local suite_label="$1"
    local dir_path="$2"
    local file_pattern="${3:-*.sh}"

    if [[ ! -d "${dir_path}" ]]; then
        echo "Warning: Directory ${dir_path} does not exist. Skipping."
        return
    fi

    local test_files
    test_files=$(find "${dir_path}" -maxdepth 1 -name "${file_pattern}" | sort)

    if [[ -z "${test_files}" ]]; then
        echo "Warning: No test scripts matching pattern '${file_pattern}' found in ${dir_path}."
        return
    fi

    for test_file in ${test_files}; do
        run_test_file "${suite_label}" "${test_file}"
    done
}

echo "================================================================================"
echo " Starting Security Test Suite Meta-Runner"
echo " Suite Filter : ${SELECTED_SUITE}"
echo " Target URL   : ${SERVER_URL}"
echo " LLM URL      : ${CONFIG_LLM_URL:-Not Configured}"
echo " Start Time   : $(date)"
echo "================================================================================"
echo ""

# Pre-flight check: Verify target assistant server is running
HEALTH_URL="${SERVER_URL%/}/health"
echo "Checking target server availability at ${HEALTH_URL}..."
if ! curl -s --connect-timeout 2 "${HEALTH_URL}" > /dev/null 2>&1; then
    echo "================================================================================"
    echo " ERROR: Assistant server is not running on localhost."
    echo " Target endpoint ${SERVER_URL} is unreachable."
    echo ""
    echo " Hint: Run ./startserver.sh in a separate terminal before starting tests."
    echo "================================================================================"
    exit 1
fi
echo "Target server is ONLINE."
echo ""

# Pre-flight check: Verify LLM reachability using configured model1.baseUrl
if [[ -n "${CONFIG_LLM_URL}" ]]; then
    CLEAN_LLM_URL="${CONFIG_LLM_URL%/}"
    echo "Checking configured LLM service availability at ${CLEAN_LLM_URL}..."
    LLM_HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${CLEAN_LLM_URL}" 2>/dev/null || echo "000")
    if [[ "${LLM_HTTP_STATUS}" == "000" ]]; then
        echo "================================================================================"
        echo " ABORT: LLM_OFFLINE"
        echo " The LLM service at ${CONFIG_LLM_URL} is unreachable."
        echo " Please ensure the configured model1 server in config.properties is active."
        echo "================================================================================"
        exit 1
    fi
    echo "LLM service is ONLINE (HTTP status: ${LLM_HTTP_STATUS})."
    echo ""
fi

GLOBAL_START_TIME="$(date +%s)"

if [[ "${SELECTED_SUITE}" == "basic" || "${SELECTED_SUITE}" == "all" ]]; then
    echo "--- Executing Suite: Basic Security Tests ---"
    run_suite_directory "basic" "${BASIC_DIR}"
    echo ""
fi

if [[ "${SELECTED_SUITE}" == "guardrail" || "${SELECTED_SUITE}" == "all" ]]; then
    echo "--- Executing Suite: Internal Security Guardrail Tests ---"
    run_suite_directory "guardrail" "${GUARDRAIL_DIR}"
    echo ""
fi

GLOBAL_END_TIME="$(date +%s)"
TOTAL_DURATION=$(( GLOBAL_END_TIME - GLOBAL_START_TIME ))

echo "=========================================================================================================================="
echo " TEST EXECUTION SUMMARY REPORT"
echo "=========================================================================================================================="
printf "%-10s | %-42s | %-3s | %-12s | %-12s | %-15s | %-12s | %-15s | %-8s\n" \
    "SUITE" "TEST NAME" "RES" "REQUEST SEC" "TRIAGE SEC" "TRIAGE EXEC" "REMED SEC" "REMED EXEC" "DURATION"
echo "--------------------------------------------------------------------------------------------------------------------------"

TOTAL_TESTS=${#TEST_NAMES[@]}
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
