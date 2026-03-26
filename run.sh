#!/bin/bash
# ============================================================
# RECON-X | run.sh
# Description: One-command launcher for RECON-X
# Usage: ./run.sh [recon-x options]
# Examples:
#   ./run.sh --help
#   ./run.sh --targets 192.168.1.1 --profile quick
# ============================================================

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Error: Virtual environment not found!"
    echo ""
    echo "👉 First run: ./setup.sh"
    echo "👉 Then run:  ./run.sh"
    exit 1
fi

# Activate virtual environment
source .venv/bin/activate

# Run RECON-X with all passed arguments
exec recon-x "$@"
