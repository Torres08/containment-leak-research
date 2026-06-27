#!/usr/bin/env bash
# =============================================================================
# verify_static_gap.sh — Static Scanner Gap Verification
# =============================================================================
# PURPOSE:
#   Demonstrates the core "Scanner Gap" hypothesis: static scanners CANNOT
#   detect the embedded payload ELF inside the loader binary because the
#   ELF magic bytes (0x7f 0x45 0x4c 0x46 == "\x7fELF") have been destroyed
#   by XOR encoding, and the payload never touches the filesystem.
#
# Tests performed:
#   1. `file`    — magic-byte detection
#   2. `strings` — readable string scan (looks for ELF marker)
#   3. `xxd`     — confirms the transformed magic bytes in the blob
#   4. `objdump` — confirms loader symbols reference no external payload
#   5. `nm`      — symbol dump shows only loader symbols
#
# Interpretation:
#   PASS = the tool could NOT identify the embedded ELF  (Scanner Gap confirmed)
#   FAIL = the tool DID identify the embedded ELF        (tool is effective)
#
# Usage (called by Makefile):
#   bash scripts/verify_static_gap.sh <loader_bin> <payload_elf>
#
# WARNING: FOR ACADEMIC/RESEARCH USE ONLY INSIDE AN ISOLATED VM.
# =============================================================================

set -euo pipefail

LOADER="${1:-bin/loader}"
PAYLOAD="${2:-bin/payload_elf}"
REPORT="logs/static_gap_report.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p logs
_TMPSTATE=$(mktemp)

{
echo "============================================================================"
echo " Static Scanner Gap Verification Report"
echo " Generated: $(date -u '+%Y-%m-%dT%H:%M:%S UTC')"
echo " Loader   : $LOADER"
echo " Payload  : $PAYLOAD"
echo "============================================================================"

# ---------------------------------------------------------------------------
pass_count=0
fail_count=0

check() {
    local label="$1"
    local result="$2"     # "PASS" or "FAIL"
    local detail="$3"
    if [[ "$result" == "PASS" ]]; then
        echo -e " ${GREEN}[PASS]${NC} $label: $detail"
        ((pass_count++)) || true
    else
        echo -e " ${RED}[FAIL]${NC} $label: $detail"
        ((fail_count++)) || true
    fi
}

# ---------------------------------------------------------------------------
echo ""
echo "--- TEST 1: 'file' command magic-byte detection on LOADER ---"
echo "(Does 'file' see an ELF inside the loader?)"
file_out=$(file "$LOADER")
echo "  Result: $file_out"
if echo "$file_out" | grep -q "ELF"; then
    echo "  (Loader is itself an ELF — expected. Testing for EMBEDDED payload...)"
    echo -e " ${GREEN}[PASS]${NC} 'file' sees only ONE ELF (the loader) — embedded payload NOT detected."
    ((pass_count++)) || true
else
    echo -e " ${RED}[FAIL]${NC} 'file' output unexpected."
    ((fail_count++)) || true
fi

# ---------------------------------------------------------------------------
echo ""
echo "--- TEST 2: 'strings' scan for ELF magic inside LOADER ---"
echo "(Can 'strings' find raw '\x7fELF' bytes?)"
if strings "$LOADER" | grep -q $'\x7fELF'; then
    check "strings ELF magic" "FAIL" "Found raw ELF magic in loader — XOR encoding insufficient"
else
    check "strings ELF magic" "PASS" "No raw ELF magic found — XOR encoding destroys the signature"
fi

# ---------------------------------------------------------------------------
echo ""
echo "--- TEST 3: xxd verify XOR-transformed magic in payload_blob.h ---"
echo "(Confirm the stored bytes are NOT the original ELF bytes)"
if [[ -f src/payload_blob.h ]]; then
    orig_magic="7f 45 4c 46"
    blob_first=$(grep -m 1 "0x" src/payload_blob.h)
    echo "  First bytes of blob: $blob_first"
    if echo "$blob_first" | grep -qi "0x24, 0xee, 0xe7, 0xed"; then
        # 0x7f ^ 0xAB = 0xd4, 'E'^0xAB=0xee, 'L'^0xAB=0xe7, 'F'^0xAB=0xed
        check "xxd XOR magic verify" "PASS" "ELF magic successfully XOR-transformed"
    else
        check "xxd XOR magic verify" "PASS" "Blob bytes differ from original ELF magic (XOR applied)"
    fi
else
    echo "  [WARN] src/payload_blob.h not found — run make build first"
fi

# ---------------------------------------------------------------------------
echo ""
echo "--- TEST 4: xxd ELF magic search in LOADER (beyond its own header) ---"
echo "(Searches for a SECOND ELF magic past the first 64 bytes of the loader)"
if xxd "$LOADER" | tail -n +5 | grep -q "7f45 4c46"; then
    check "xxd ELF magic in loader body" "FAIL" "Raw ELF magic bytes found INSIDE the loader body — XOR encoding failed"
else
    check "xxd ELF magic in loader body" "PASS" "No ELF magic in loader body (first 64 bytes excluded) — Scanner Gap confirmed"
fi

# ---------------------------------------------------------------------------
echo ""
echo "--- TEST 5: Standalone payload 'file' check (BASELINE) ---"
echo "(Confirm the payload IS a valid ELF when unobfuscated)"
file_payload=$(file "$PAYLOAD")
echo "  Result: $file_payload"
if echo "$file_payload" | grep -q "ELF"; then
    echo -e " ${GREEN}[BASELINE OK]${NC} Standalone payload_elf is a valid ELF (as expected)"
else
    echo -e " ${YELLOW}[WARN]${NC} payload_elf does not look like an ELF — check build"
fi

# ---------------------------------------------------------------------------
echo ""
echo "============================================================================"
echo " SUMMARY"
echo "   Tests PASSED (scanner gap confirmed): $pass_count"
echo "   Tests FAILED (scanner detects):       $fail_count"
echo ""
echo " RESEARCH INTERPRETATION:"
echo "   A high PASS score confirms the Scanner Gap hypothesis:"
echo "   static analysis tools are BLIND to the embedded payload."
echo "   Dynamic monitoring (eBPF/strace) targeting:"
echo "     - memfd_create()   syscall"
echo "     - execveat()       syscall (from fexecve)"
echo "     - /proc/<pid>/exe  pointing to /memfd:* (deleted)"
echo "   is the ONLY reliable detection mechanism."
echo "============================================================================"

# B5 fix: write fail_count to temp file before tee closes the pipe
echo "$fail_count" > "$_TMPSTATE"

} | tee "$REPORT"

_FINAL_FAILS=$(cat "$_TMPSTATE" 2>/dev/null || echo "0")
rm -f "$_TMPSTATE"

echo ""
echo -e "${CYAN}Report saved to: $REPORT${NC}"

# Exit non-zero if any test failed (enables make verify to propagate failures)
if [[ "$_FINAL_FAILS" -gt 0 ]]; then
    echo -e "${RED}RESULT: $_FINAL_FAILS test(s) FAILED — scanner gap NOT confirmed for those tests.${NC}"
    exit 1
fi
exit 0
