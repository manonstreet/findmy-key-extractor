#!/bin/bash
#
# extract_localstorage_key.sh — Extract the AES-256 key for LocalStorage.db
#
# Orchestrates: lldb attach -> breakpoint capture -> verify key -> chown
#
# Usage:
#   cd findmy-cache-decryptor
#   ./extract_localstorage_key.sh
#
# Prerequisites:
#   - SIP disabled + amfi_get_out_of_my_way=1
#   - findmylocateagent running (open Find My app first, or it starts on demand)
#   - pip3 install -r requirements.txt
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SETUP_DIR="$HOME/FindMySyncPlus/setup"
KEY_FILE="$SETUP_DIR/localstorage.key"
KEY1_FILE="$SETUP_DIR/key_1.bin"
KEY2_FILE="$SETUP_DIR/key_2.bin"

echo "=== LocalStorage.db key extractor ==="
echo ""

# 1. Check findmylocateagent is running
PID=$(pgrep -x findmylocateagent 2>/dev/null || true)
if [ -z "$PID" ]; then
    echo "findmylocateagent is not running."
    echo ""
    echo "To start it:"
    echo "  1. Open the Find My app"
    echo "  2. Wait a few seconds for the agent to spawn"
    echo "  3. Re-run this script"
    echo ""
    echo "Or to attach before it starts:"
    echo "  sudo lldb --wait-for -n findmylocateagent \\"
    echo "    -o \"command script import $SCRIPT_DIR/extract_key.py\" -o \"c\""
    exit 1
fi
echo "Found findmylocateagent (PID $PID)"

# 2. Create output directory
mkdir -p "$SETUP_DIR"

# 3. Clean up any previous fallback keys
rm -f "$KEY1_FILE" "$KEY2_FILE"

# 4. Run lldb with extract_key.py
echo ""
echo "Attaching lldb to findmylocateagent..."
echo ">>> You may need to open Find My app now to trigger key derivation <<<"
echo ""

sudo lldb -p "$PID" \
    -o "command script import $SCRIPT_DIR/extract_key.py" \
    -o "c"

echo ""

# 5. Chown any output files back to the current user
if [ -f "$KEY_FILE" ]; then
    sudo chown "$(whoami)" "$KEY_FILE"
fi
for f in "$KEY1_FILE" "$KEY2_FILE"; do
    if [ -f "$f" ]; then
        sudo chown "$(whoami)" "$f"
    fi
done

# 6. Resolve fallback keys if needed
if [ -f "$KEY1_FILE" ] || [ -f "$KEY2_FILE" ]; then
    echo "Resolving fallback keys..."
    python3 "$SCRIPT_DIR/verify_key.py" --resolve-fallback
    VERIFY_RC=$?
elif [ -f "$KEY_FILE" ]; then
    echo "Verifying key..."
    python3 "$SCRIPT_DIR/verify_key.py" "$KEY_FILE"
    VERIFY_RC=$?
else
    echo "ERROR: No key files were captured."
    echo "Make sure Find My app is open and try again."
    exit 1
fi

echo ""
if [ "$VERIFY_RC" -eq 0 ]; then
    echo "Key extracted and verified successfully."
    echo "  $KEY_FILE ($(wc -c < "$KEY_FILE" | tr -d ' ') bytes)"
    echo ""
    echo "You can now run:"
    echo "  python3 decrypt_localstorage.py"
else
    echo "Key verification FAILED."
    echo "The captured key does not decrypt LocalStorage.db correctly."
    echo "Try killing findmylocateagent (kill -9 $PID), reopening Find My, and running again."
    exit 1
fi
