#!/usr/bin/env bash

# Start script for Python FastAPI EmbeddedServer listening for ticket requests on port 8080

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${SCRIPT_DIR}"

VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"
if [[ ! -x "${VENV_PYTHON}" ]]; then
    VENV_PYTHON="python3"
fi

PORT=$(grep -E '^server\.port=' config.properties 2>/dev/null | cut -d'=' -f2 | tr -d ' \r' )

echo "================================================================================"
echo " Starting Enterprise IT Assistant Python EmbeddedServer..."
echo " Target Port: ${PORT}"
echo " Python Binary: ${VENV_PYTHON}"
echo "================================================================================"

"${VENV_PYTHON}" -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
