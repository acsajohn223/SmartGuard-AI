#!/usr/bin/env bash
#
# SmartGuard AI - one-shot environment setup.
#
# Creates a virtual environment, installs the Python dependencies and
# installs the solc compiler version used by Slither.
#
# Usage:  bash scripts/setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/../backend"
VENV_DIR="${BACKEND_DIR}/.venv"

SOLC_VERSION="${SMARTGUARD_SOLC_VERSION:-0.8.20}"

# --- 1. Pick a suitable Python ------------------------------------------
# SmartGuard AI needs Python 3.8 or newer. We look for the newest
# interpreter available so that the PEP 585/604 syntax in the source
# works without any backport.
find_python() {
    for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            if "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
                command -v "${candidate}"
                return 0
            fi
        fi
    done
    return 1
}

if ! PYTHON_BIN="$(find_python)"; then
    echo "ERROR: No Python 3.8+ interpreter found." >&2
    echo "       Install Python 3.9+ from https://www.python.org/downloads/macos/" >&2
    exit 1
fi

PYTHON_VERSION="$("${PYTHON_BIN}" -c 'import platform; print(platform.python_version())')"
echo "==> Using ${PYTHON_BIN} (Python ${PYTHON_VERSION})"

# --- 2. Virtual environment --------------------------------------------
echo "==> Creating virtual environment at ${VENV_DIR}"
if [ ! -x "${VENV_DIR}/bin/python" ]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
else
    echo "    (reusing the existing virtual environment)"
fi

echo "==> Upgrading pip"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip

echo "==> Installing backend dependencies"
"${VENV_DIR}/bin/python" -m pip install -r "${BACKEND_DIR}/requirements.txt"

# --- 3. Compiler --------------------------------------------------------
# Slither needs a real solc binary. solc-select fetches it into
# ~/.solc-select/artifacts/. If that fails (offline, blocked mirror,
# unusual platform) we fall back to a direct download so that the setup
# still completes.
install_solc() {
    echo "==> Installing solc ${SOLC_VERSION} via solc-select"
    "${VENV_DIR}/bin/solc-select" install "${SOLC_VERSION}" \
        && "${VENV_DIR}/bin/solc-select" use "${SOLC_VERSION}"
}

install_solc_manual() {
    echo "==> solc-select could not fetch solc, downloading it directly"

    local platform_dir
    case "$(uname -s)" in
        Darwin) platform_dir="macosx-amd64" ;;
        Linux)  platform_dir="linux-amd64" ;;
        *)      platform_dir="" ;;
    esac
    [ -n "${platform_dir}" ] || { echo "ERROR: unsupported platform" >&2; return 1; }

    local base="https://binaries.soliditylang.org/${platform_dir}"
    local url
    url="$(curl -fsSL "${base}/list.json" \
           | python3 -c "
import json, sys
data = json.load(sys.stdin)
path = data['releases'].get('${SOLC_VERSION}')
print(f\"{base}/{path}\" if path else '')
" 2>/dev/null)" || url=""

    if [ -z "${url}" ]; then
        echo "ERROR: could not resolve a solc ${SOLC_VERSION} download URL" >&2
        return 1
    fi

    local install_dir="${HOME}/.solc-select/artifacts/solc-${SOLC_VERSION}"
    mkdir -p "${install_dir}"
    echo "    downloading ${url}"
    curl -fsSL "${url}" -o "${install_dir}/solc-${SOLC_VERSION}"
    chmod +x "${install_dir}/solc-${SOLC_VERSION}"
    echo "${SOLC_VERSION}" > "${HOME}/.solc-select/global-version"
}

if ! install_solc; then
    echo
    echo "    solc-select failed, trying a direct download..."
    install_solc_manual
fi

# --- 4. Verify ----------------------------------------------------------
echo
echo "==> Verifying the installation"
(cd "${BACKEND_DIR}" && "${VENV_DIR}/bin/python" -c "
from app.core.config import Settings
from app.modules.slither_scanner import SlitherScannerModule
from collections import Counter
scanner = SlitherScannerModule(Settings())
_, detectors = scanner._load_slither()
counts = Counter(scanner._impact_of(d) for d in detectors)
print(f'    Slither detectors: {counts[\"High\"]} High + {counts[\"Medium\"]} Medium = {counts[\"High\"] + counts[\"Medium\"]}')
")

echo
echo "==> Setup complete."
echo "    Start the API :  cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000"
echo "    Start the UI  :  cd frontend && python3 -m http.server 3000"
echo "    Then open      :  http://localhost:3000"
