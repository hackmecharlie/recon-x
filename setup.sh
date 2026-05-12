#!/bin/bash
# ============================================================
# RECON-X | setup.sh
# Description: One-command setup script for RECON-X
# Usage: ./setup.sh
# ============================================================

set -euo pipefail

echo "RECON-X Setup"
echo "============="

warn() {
    echo "[WARN] $1"
}

info() {
    echo "[INFO] $1"
}

ok() {
    echo "[OK]   $1"
}

install_linux_packages_if_possible() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        warn "Non-Linux OS detected. Skipping system package auto-install."
        return 0
    fi

    local pkgs=(nmap libpango-1.0-0 libpangoft2-1.0-0)

    if command -v apt-get >/dev/null 2>&1; then
        if command -v sudo >/dev/null 2>&1; then
            info "Installing Linux dependencies via apt-get: ${pkgs[*]}"
            sudo apt-get update && sudo apt-get install -y "${pkgs[@]}" || warn "apt-get install failed; continuing."
        elif [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
            info "Installing Linux dependencies via apt-get as root: ${pkgs[*]}"
            apt-get update && apt-get install -y "${pkgs[@]}" || warn "apt-get install failed; continuing."
        else
            warn "apt-get available but sudo/root not available; skipping system package install."
            warn "Install manually: sudo apt-get install -y ${pkgs[*]}"
        fi
    else
        warn "No supported package manager detected (apt-get). Install manually: ${pkgs[*]}"
    fi
}

verify_binary() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        ok "$name found"
    else
        warn "$name not found"
    fi
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "[ERROR] Python 3.10+ required. Found: $PYTHON_VERSION"
    exit 1
fi

ok "Python version: $PYTHON_VERSION"

install_linux_packages_if_possible

if [ ! -d ".venv" ]; then
    info "Creating virtual environment (.venv)"
    python3 -m venv .venv
    ok "Virtual environment created"
else
    ok "Virtual environment already exists"
fi

info "Activating virtual environment"
source .venv/bin/activate

info "Upgrading pip/setuptools/wheel"
pip install --upgrade pip setuptools wheel

info "Installing Python dependencies"
pip install -r requirements.txt

info "Installing RECON-X in editable mode"
pip install -e .

info "Installing Playwright Chromium"
python -m playwright install chromium

echo
echo "Post-setup verification"
echo "-----------------------"
verify_binary recon-x
verify_binary nmap

python - <<'PY'
import importlib
mods = [
    "jinja2",
    "impacket",
    "nmap",
    "playwright",
]
missing = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception:
        missing.append(m)

if missing:
    print("[WARN] Missing Python modules:", ", ".join(missing))
else:
    print("[OK]   Core Python modules import successfully")
PY

echo
ok "Setup complete"
echo
echo "Next steps:"
echo "  1) Run a scan: ./run.sh --targets 127.0.0.1 --profile quick --yes"
echo "  2) Show help: ./run.sh --help"
