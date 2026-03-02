#!/bin/bash
#
# extract_keys_all.sh — Extract all Find My keys in one shot (parallel)
#
# Launches two lldb sessions simultaneously:
#   1. findmylocateagent → LocalStorage.db key (sqlite3_key_v2)
#   2. FindMy.app        → FMF/FMIP keychain items (SecItemCopyMatching)
#
# Usage:
#   cd findmy-key-extractor
#   ./extract.sh
#
# Prerequisites:
#   - SIP disabled + amfi_get_out_of_my_way=1
#   - pip3 install -r requirements.txt (for verification)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
LOG1=$(mktemp /tmp/lldb_locateagent.XXXXXX)
LOG2=$(mktemp /tmp/lldb_findmy.XXXXXX)

cleanup() {
    rm -f "$LOG1" "$LOG2"
}
trap cleanup EXIT

# ── Prime sudo (before banner so password prompt isn't buried) ────────────
sudo -v

echo ""
echo "  🔑  Find My Key Extractor"
echo "  ─────────────────────────"
echo ""
echo "  ⏳  Extracting keys (~10s)..."

# ── Kill everything ───────────────────────────────────────────────────────
pkill -9 FindMy 2>/dev/null || true
sudo pkill -9 findmylocateagent 2>/dev/null || true
sleep 0.5

# ── Prepare output directory ─────────────────────────────────────────────
mkdir -p "$KEYS_DIR"
rm -f "$KEYS_DIR"/LocalStorage.key
rm -f "$KEYS_DIR"/*.bplist

# ── Launch both lldb sessions in parallel ─────────────────────────────────

sudo lldb --wait-for -n findmylocateagent \
    -o "settings set frame-format ''" \
    -o "settings set auto-confirm true" \
    -o "command script import $SCRIPT_DIR/extract_db_key.py" \
    -o "c" \
    -o "quit" > "$LOG1" 2>&1 &
PID1=$!

sudo lldb --wait-for -n FindMy \
    -o "settings set frame-format ''" \
    -o "settings set auto-confirm true" \
    -o "command script import $SCRIPT_DIR/extract_keychain_keys.py" \
    -o "c" \
    -o "quit" > "$LOG2" 2>&1 &
PID2=$!

# ── Open Find My after a brief delay (triggers both processes) ────────────
sleep 2
open /System/Applications/FindMy.app

# ── Wait for both lldb sessions to finish ─────────────────────────────────
wait "$PID1" 2>/dev/null || true
wait "$PID2" 2>/dev/null || true

# ── Kill Find My, chown captured files ────────────────────────────────────
pkill -9 FindMy 2>/dev/null || true

ME=$(whoami)
for f in "$KEYS_DIR"/LocalStorage.key "$KEYS_DIR"/*.bplist; do
    [ -f "$f" ] && sudo chown "$ME" "$f" 2>/dev/null || true
done

# ── Extraction summary ────────────────────────────────────────────────────
echo ""
echo "  ── Extraction ──"
echo ""

FAIL=0

if [ -f "$KEYS_DIR/LocalStorage.key" ]; then
    SIZE=$(wc -c < "$KEYS_DIR/LocalStorage.key" | tr -d ' ')
    echo "  ✅  LocalStorage.key ($SIZE bytes)"
else
    echo "  ❌  LocalStorage.key — not captured"
    FAIL=1
fi

for NAME in FMFDataManager FMIPDataManager; do
    FILE="$KEYS_DIR/$NAME.bplist"
    if [ -f "$FILE" ]; then
        SIZE=$(wc -c < "$FILE" | tr -d ' ')
        echo "  ✅  $NAME.bplist ($SIZE bytes)"
    else
        echo "  ❌  $NAME.bplist — not captured"
        FAIL=1
    fi
done

# ── Verification ──────────────────────────────────────────────────────────
echo ""
echo "  ── Verification ──"
echo ""

for KEYFILE in "$KEYS_DIR"/LocalStorage.key "$KEYS_DIR"/*.bplist; do
    [ -f "$KEYFILE" ] && python3 "$SCRIPT_DIR/verify_key.py" "$KEYFILE" 2>&1 || FAIL=1
done

# On failure, show relevant lines from lldb logs
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "  ── Debug ──"
    echo ""
    grep -h '⚠️\|❌' "$LOG1" "$LOG2" 2>/dev/null | head -20 || true
fi

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "  💾 Saved to ./keys/"
fi

echo ""
