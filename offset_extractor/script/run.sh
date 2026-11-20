#!/bin/bash
# ==============================================================================
# Omega-REA Automated Offset Extractor Multi-Target Runner Script
# Usage:
#   ./run.sh                  (Scans for both daemon archives and libUE4.so binaries)
#   ./run.sh <file_or_zip>    (Automatically detects target type and extracts offsets)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCK_EXTRACTOR="$SCRIPT_DIR/extract_offsets.py"
LIBUE4_EXTRACTOR="$SCRIPT_DIR/extract_from_libue4.py"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

if [ ! -f "$SOCK_EXTRACTOR" ] || [ ! -f "$LIBUE4_EXTRACTOR" ]; then
    echo "[!] Error: Required extraction scripts not found in $SCRIPT_DIR"
    exit 1
fi

if [ "$#" -eq 0 ]; then
    echo "================================================================================"
    echo " OMEGA-REA MULTI-TARGET OFFSET EXTRACTION: BATCH AUTO-DISCOVERY MODE"
    echo "================================================================================"
    
    # 1. Run sock64b / xalldatq daemon extraction
    echo ""
    echo "[*] Phase 1: Scanning daemon payloads (sock64b / xalldatq archives)..."
    python3 "$SOCK_EXTRACTOR"

    # 2. Run libUE4.so extraction if reconstructed reference exists in Originals/
    echo ""
    echo "[*] Phase 2: Scanning reconstructed game libraries (libUE4.so / libUE4_v4_7.so)..."
    FOUND_SO=0
    for cand in "$WORKSPACE_ROOT/Originals"/libUE4*.so "$SCRIPT_DIR/../original_files"/libUE4*.so; do
        if [ -f "$cand" ]; then
            FOUND_SO=1
            echo "[*] Found reconstructed game library: $cand"
            python3 "$LIBUE4_EXTRACTOR" "$cand"
        fi
    done

    if [ "$FOUND_SO" -eq 0 ]; then
        echo "[i] Note: No libUE4*.so files found in Originals/ or original_files/."
        echo "    To extract directly from the game library, dump it with UE4Dumper and place in Originals/."
    fi

    echo ""
    echo "[+] Batch extraction complete. Reports saved in 'generated_offsets/'."
else
    TARGET="$1"
    if [ ! -f "$TARGET" ]; then
        echo "[!] Error: Target file does not exist: $TARGET"
        exit 1
    fi

    echo "[*] Running extraction on target: $TARGET"
    FILENAME=$(basename "$TARGET")

    # Routing based on file type / name
    if [[ "$FILENAME" == *.so* ]] || [[ "$FILENAME" == *libUE4* ]]; then
        echo "[*] Routing to libUE4.so Direct Extractor..."
        python3 "$LIBUE4_EXTRACTOR" "$TARGET"
    elif [[ "$FILENAME" == *.zip* ]] || [[ "$FILENAME" == *sock* ]]; then
        echo "[*] Routing to sock64b Daemon Table Extractor..."
        python3 "$SOCK_EXTRACTOR" "$TARGET"
    else
        # Inspect ELF / archive header
        MAGIC=$(head -c 4 "$TARGET")
        if [ "$MAGIC" = "PK"$'\x03'$'\x04' ]; then
            echo "[*] Target identified as ZIP archive. Routing to sock64b Daemon Extractor..."
            python3 "$SOCK_EXTRACTOR" "$TARGET"
        elif [ "$MAGIC" = $'\x7f'"ELF" ]; then
            # Check size: libUE4 is typically > 50 MB, sock64b is < 5 MB
            FSIZE=$(stat -c%s "$TARGET")
            if [ "$FSIZE" -gt 10000000 ]; then
                echo "[*] Target identified as large ELF (>10MB). Routing to libUE4.so Direct Extractor..."
                python3 "$LIBUE4_EXTRACTOR" "$TARGET"
            else
                echo "[*] Target identified as daemon ELF (<10MB). Routing to sock64b Daemon Extractor..."
                python3 "$SOCK_EXTRACTOR" "$TARGET"
            fi
        else
            echo "[!] Unrecognized target format. Defaulting to sock64b extractor..."
            python3 "$SOCK_EXTRACTOR" "$TARGET"
        fi
    fi
fi
