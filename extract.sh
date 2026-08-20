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
#   - Python deps for verification: see README Step 2 (a .venv beside this
#     script is picked up automatically)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"

LOG1=$(mktemp /tmp/lldb_locateagent.XXXXXX)
LOG2=$(mktemp /tmp/lldb_findmy.XXXXXX)

# FindMy.app is App-Sandboxed, so extract_keychain_keys.py can't write the
# FMF/FMIP bplists directly into $KEYS_DIR from inside it — it writes them
# to the app's own sandbox-writable container tmp dir instead, and we copy
# them out from here as the normal (unsandboxed) user below.
FINDMY_TMP_DIR="$HOME/Library/Containers/com.apple.findmy/Data/tmp"

# Keep the lldb logs when a run fails. They are the only record of *why* — a
# Python traceback from a breakpoint callback appears nowhere else — and deleting
# them unconditionally is why past failures took weeks to diagnose.
KEEP_LOGS=0
cleanup() {
    if [ "$KEEP_LOGS" = "1" ]; then
        mkdir -p "$SCRIPT_DIR/logs"
        cp -f "$LOG1" "$SCRIPT_DIR/logs/lldb_locateagent.log" 2>/dev/null || true
        cp -f "$LOG2" "$SCRIPT_DIR/logs/lldb_findmy.log" 2>/dev/null || true
        echo ""
        echo "  📝  lldb logs kept in ./logs/ — attach them to your issue"
    fi
    rm -f "$LOG1" "$LOG2"
}
trap cleanup EXIT

# ── Python for the verification step ──────────────────────────────────────
#
# Prefer a venv next to this script, so the caller doesn't have to remember to
# activate it. Apple's /usr/bin/python3 permits `pip3 install`; Homebrew's
# refuses it (PEP 668, "externally-managed-environment"), so a venv is the one
# path that works on every interpreter.
#
# Setup is opt-in rather than automatic: this script runs sudo lldb against
# system processes on a machine with SIP disabled, and silently fetching code
# from PyPI on top of that is not a thing to do without being asked.
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="$VENV_DIR/bin/python3"
[ -x "$PYTHON" ] || PYTHON="$(command -v python3 || true)"

have_deps() {
    [ -n "$PYTHON" ] && "$PYTHON" -c "import Crypto, cryptography" 2>/dev/null
}

if [ "${1:-}" = "--setup" ]; then
    echo ""
    echo "  🔧  Setting up the verification dependencies"
    echo ""
    if [ ! -x "$VENV_DIR/bin/python3" ]; then
        echo "  →  creating $VENV_DIR"
        python3 -m venv "$VENV_DIR" || { echo "  ❌  could not create the virtualenv"; exit 1; }
    fi
    PYTHON="$VENV_DIR/bin/python3"
    echo "  →  installing $(tr '\n' ' ' < "$SCRIPT_DIR/requirements.txt")"
    # Upgrade pip first: the system pip that ships with Apple's python3 is old
    # enough to resolve wheels poorly.
    "$PYTHON" -m pip install --quiet --upgrade pip || true
    # --only-binary: cryptography needs a Rust toolchain to build from source,
    # which most machines running this do not have. Wheels only means it either
    # installs cleanly or fails immediately with a clear reason, instead of
    # starting a compile that cannot finish.
    if ! "$PYTHON" -m pip install --quiet --only-binary=:all: -r "$SCRIPT_DIR/requirements.txt"; then
        echo "  ❌  Could not install prebuilt wheels for this Python."
        echo ""
        echo "      $("$PYTHON" -V 2>&1) on $(uname -m) may not have wheels for"
        echo "      every dependency. Options:"
        echo "        • use a newer python3 (3.11+ has the widest wheel coverage)"
        echo "        • or install a Rust toolchain and retry without --only-binary"
        exit 1
    fi
    have_deps || { echo "  ❌  dependencies still not importable"; exit 1; }
    echo ""
    echo "  ✅  Ready. Now run: ./extract.sh"
    echo ""
    exit 0
fi

# Check before doing any work: without this the whole lldb extraction runs and
# only *then* fails on an ImportError, which reads as "key extraction failed"
# when the keys were actually fine.
if ! have_deps; then
    echo ""
    echo "  ❌  Missing Python dependencies (pycryptodome, cryptography)."
    echo ""
    echo "      Run:  ./extract.sh --setup"
    echo ""
    echo "      That creates a virtualenv in .venv and installs them there."
    echo "      Nothing else on your system is touched. To do it by hand:"
    echo "        python3 -m venv .venv && source .venv/bin/activate"
    echo "        pip install -r requirements.txt"
    echo ""
    exit 1
fi

# ── Prime sudo (before banner so password prompt isn't buried) ────────────
sudo -v

echo ""
echo "  🔑  Find My Key Extractor"
echo "  ─────────────────────────"
echo ""
echo "  ⏳  Extracting keys (~10s)..."

# ── Pre-kill stale lldb instances and FindMy.app (NOT findmylocateagent yet —
#    we need lldb to be in --wait-for state BEFORE we kill it, otherwise
#    launchd respawns it before lldb starts waiting and --wait-for never fires.
#    `pkill lldb` matches by exec name, so it kills the lldb children of any
#    `sudo lldb` wrappers; their sudo parents exit when the child dies.) ────
sudo pkill -9 lldb 2>/dev/null || true
pkill -9 FindMy 2>/dev/null || true
sleep 0.5

# ── Prepare output directory ─────────────────────────────────────────────
mkdir -p "$KEYS_DIR"
rm -f "$KEYS_DIR"/LocalStorage.key
rm -f "$KEYS_DIR"/LocalStorage.key.candidate
rm -f "$KEYS_DIR"/*.bplist
rm -f "$FINDMY_TMP_DIR"/*.bplist 2>/dev/null || true

# ── Launch both lldb sessions in parallel — they enter --wait-for state ───
sudo lldb --wait-for -n findmylocateagent \
    -o "settings set frame-format ''" \
    -o "settings set auto-confirm true" \
    -o "command script import $SCRIPT_DIR/extract_db_key.py" \
    -o "process continue" > "$LOG1" 2>&1 &
PID1=$!

sudo lldb --wait-for -n FindMy \
    -o "settings set frame-format ''" \
    -o "settings set auto-confirm true" \
    -o "command script import $SCRIPT_DIR/extract_keychain_keys.py" \
    -o "process continue" > "$LOG2" 2>&1 &
PID2=$!

# ── Give the lldb waiters a moment to install themselves ──────────────────
sleep 1

# ── NOW restart findmylocateagent via launchctl — `pkill -9` is unreliable
#    here (the daemon survives SIGKILL on some configurations, possibly due
#    to launchd protection or a stuck-zombie state). `kickstart -k` cleanly
#    stops and restarts via launchd's own mechanism so the waiting lldb
#    catches the fresh PID. The agent runs in the per-user GUI domain. ────
USER_UID=$(id -u "$(stat -f %Su /dev/console)")
sudo launchctl kickstart -k "gui/$USER_UID/com.apple.findmy.findmylocateagent" 2>/dev/null || true
sleep 1
open /System/Applications/FindMy.app

# ── Wait up to 45s for keys (scripts kill targets when done) ──────────────
for _ in $(seq 1 45); do
    # Copy any FMF/FMIP bplists out of FindMy's sandbox container as soon
    # as they show up (extract_keychain_keys.py can't write $KEYS_DIR
    # directly from inside the sandboxed process).
    for NAME in FMFDataManager FMIPDataManager; do
        SRC="$FINDMY_TMP_DIR/$NAME.bplist"
        DST="$KEYS_DIR/$NAME.bplist"
        if [ -f "$SRC" ] && [ ! -f "$DST" ]; then
            cp "$SRC" "$DST" 2>/dev/null || true
        fi
    done

    got=0
    if [ -f "$KEYS_DIR/LocalStorage.key" ] || [ -f "$KEYS_DIR/LocalStorage.key.candidate" ]; then
        got=$((got+1))
    fi
    [ -f "$KEYS_DIR/FMFDataManager.bplist" ] && got=$((got+1))
    [ -f "$KEYS_DIR/FMIPDataManager.bplist" ] && got=$((got+1))
    if [ "$got" -ge 3 ]; then
        break
    fi
    # Also done if both lldb sessions exited
    if ! kill -0 "$PID1" 2>/dev/null && ! kill -0 "$PID2" 2>/dev/null; then
        break
    fi
    sleep 1
done

sudo kill -9 "$PID1" "$PID2" 2>/dev/null || true
wait "$PID1" 2>/dev/null || true
wait "$PID2" 2>/dev/null || true

# One last copy pass in case a bplist landed in the sandbox tmp dir right
# as the loop above exited.
for NAME in FMFDataManager FMIPDataManager; do
    SRC="$FINDMY_TMP_DIR/$NAME.bplist"
    DST="$KEYS_DIR/$NAME.bplist"
    if [ -f "$SRC" ] && [ ! -f "$DST" ]; then
        cp "$SRC" "$DST" 2>/dev/null || true
    fi
done

# Promote verified candidate if needed
if [ ! -f "$KEYS_DIR/LocalStorage.key" ] && [ -f "$KEYS_DIR/LocalStorage.key.candidate" ]; then
    if "$PYTHON" "$SCRIPT_DIR/verify_key.py" "$KEYS_DIR/LocalStorage.key.candidate" >/dev/null 2>&1; then
        mv "$KEYS_DIR/LocalStorage.key.candidate" "$KEYS_DIR/LocalStorage.key"
    fi
fi

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
    [ -f "$KEYFILE" ] && "$PYTHON" "$SCRIPT_DIR/verify_key.py" "$KEYFILE" 2>&1 || FAIL=1
done

# On failure, show relevant lines from lldb logs
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "  ── Debug ──"
    echo ""
    KEEP_LOGS=1
    # The emoji lines are our own; the real cause is usually a Python traceback
    # or an lldb error, which matches none of them.
    grep -hE '⚠️|❌|Traceback|Error|error:|KeyError|Exception|RuntimeError|failed' \
        "$LOG1" "$LOG2" 2>/dev/null | grep -v "^  *$" | tail -30 || true
fi

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "  💾 Saved to ./keys/"
fi

echo ""
