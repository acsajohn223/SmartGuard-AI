#!/usr/bin/env bash
#
# SmartGuard AI - one-shot environment setup.
#
# Creates a virtual environment, installs the Python dependencies and
# pins the solc compiler version used by Slither.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/../backend"
VENV_DIR="${BACKEND_DIR}/.venv"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "==> Creating virtual environment at ${VENV_DIR}"
cd "${BACKEND_DIR}"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"

echo "==> Upgrading pip"
"${VENV_DIR}/bin/pip" install --upgrade pip

echo "==> Installing backend dependencies"
"${VENV_DIR}/bin/pip" install -r requirements.txt

echo "==> Installing solc ${SMARTGUARD_SOLC_VERSION:-0.8.20}"
"${VENV_DIR}/bin/solc-select" install "${SMARTGUARD_SOLC_VERSION:-0.8.20}"
"${VENV_DIR}/bin/solc-select" use "${SMARTGUARD_SOLC_VERSION:-0.8.20}"

echo
echo "==> Setup complete."
echo "    Start the API :  cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000"
echo "    Start the UI  :  cd frontend && python3 -m http.server 3000"
