#!/usr/bin/env bash

# Test runner script for langchain-enterprise-incident-assistant

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${SCRIPT_DIR}"

VENV_PYTEST="${ROOT_DIR}/.venv/bin/pytest"
if [[ ! -x "${VENV_PYTEST}" ]]; then
    if [[ -x "${SCRIPT_DIR}/.venv/bin/pytest" ]]; then
        VENV_PYTEST="${SCRIPT_DIR}/.venv/bin/pytest"
    else
        VENV_PYTEST="pytest"
    fi
fi

export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

echo "================================================================================"
echo " Running Unit and Integration Tests..."
echo " Pytest Binary: ${VENV_PYTEST}"
echo " Working Dir:   ${SCRIPT_DIR}"
echo "================================================================================"

exec "${VENV_PYTEST}" "$@"
