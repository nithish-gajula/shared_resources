#!/bin/bash
# ==============================================================================
# sock64b Offset Extractor Runner Script
# Usage:
#   ./run.sh                  (Scans original_files/ directory for all archives/binaries)
#   ./run.sh <file_or_zip>    (Extracts offsets from a specific sock64b binary or zip)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/extract_offsets.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "[!] Error: Extraction script not found at $PYTHON_SCRIPT"
    exit 1
fi

if [ "$#" -eq 0 ]; then
    echo "[*] Running extraction in batch auto-discovery mode..."
    python3 "$PYTHON_SCRIPT"
else
    echo "[*] Running extraction on target: $1"
    python3 "$PYTHON_SCRIPT" "$1"
fi
