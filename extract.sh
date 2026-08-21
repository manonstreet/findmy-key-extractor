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
KEEP_LOGS="${KEEP_LOGS:-0}"
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

# ── Arguments ─────────────────────────────────────────────────────────────
DO_SETUP=0
ARG_WAIT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --setup) DO_SETUP=1; shift ;;
        --wait)  ARG_WAIT="${2:-}"; shift 2 ;;
        --wait=*) ARG_WAIT="${1#*=}"; shift ;;
        -h|--help)
            echo "usage: ./extract.sh [--setup] [--wait SECONDS]"
            echo "  --setup         create .venv and install the verification deps"
            echo "  --wait SECONDS  how long to wait for Find My to read each key"
            echo "                  (default 180; slow or virtualised machines need more)"
            exit 0 ;;
        *) echo "unknown option: $1 — try --help" >&2; exit 2 ;;
    esac
done
if ! [ "${ARG_WAIT:-180}" -gt 0 ] 2>/dev/null; then
    echo "--wait needs a positive number of seconds" >&2; exit 2
fi

# How long to wait for Find My to read each keychain item. 45s was the original
# budget and is too short on slow or virtualised hardware: the two items are read
# at different moments, so a short wait can capture FMF and miss FMIP entirely —
# observed on a 2014 Mac mini, reported independently from a Proxmox VM.
# Assigned here, before anything prints it. FINDMY_WAIT_SECONDS still works.
WAIT_SECONDS="${FINDMY_WAIT_SECONDS:-180}"
[ -n "${ARG_WAIT:-}" ] && WAIT_SECONDS="$ARG_WAIT"
ELAPSED=0
# How many times to reattach if the locateagent session dies without the key.
LOCATE_RETRIES=2
# EXPERIMENT: how many times to relaunch Find My when it never asks for a key,
# and how long to wait after the first keychain read for the second one.
FINDMY_RELAUNCHES=3
# Proportional to the wait, not a fixed number of seconds. 10s was derived on an
# M4 Max, where FMF and FMIP arrive within a second of each other — but the whole
# reason the default wait is 180 is that on a 2014 mini the two reads land tens
# of seconds apart, which is what made 45s too short there. A fixed 10s grace
# would relaunch that machine moments before it was about to succeed, turning a
# slow success into a failure. A quarter of the budget gives 45s at the default
# and 11s at --wait 45, which is what was measured here.
# How long a capture is given to finish after its read before the relaunch
# is allowed to kill the process. Protects the in-flight window, nothing more.
# Time granted to each relaunched attempt. A clean capture lands in 7-15s.
ATTEMPT_BUDGET=25
CAPTURE_SETTLE=8
READ_GRACE=$((WAIT_SECONDS / 4))
[ "$READ_GRACE" -lt 8 ] && READ_GRACE=8

if [ "$DO_SETUP" = "1" ]; then
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

# ── Refuse to run alongside FindMySyncPlus ────────────────────────────────
# FMS+ launches and kills the Find My app on a timer to force a cache refresh
# (autoLaunchKillFindMy). This script attaches to and kills the same process, so
# the two fight: lldb sessions die mid-capture and keys go missing at random.
# The resulting failures look exactly like a bug in here, so stop rather than
# produce a misleading result.
if pgrep -qx FindMySyncPlus 2>/dev/null; then
    echo ""
    echo "  ❌  FindMySyncPlus is running."
    echo ""
    echo "      It launches and kills the Find My app on a timer, which"
    echo "      interferes with key extraction and causes keys to be missed"
    echo "      at random. Quit it, then run this again."
    echo ""
    echo "      (Turning the scheduler off is not enough if the app is open —"
    echo "       quit it entirely.)"
    echo ""
    exit 1
fi

# ── Prime sudo (before banner so password prompt isn't buried) ────────────
sudo -v

echo ""
echo "  🔑  Find My Key Extractor"
echo "  ─────────────────────────"
echo ""
echo "  ⏳  Waiting for Find My to read its keys (up to ${WAIT_SECONDS}s)..."
echo ""

# ── Pre-kill stale lldb instances and FindMy.app (NOT findmylocateagent yet —
#    we need lldb to be in --wait-for state BEFORE we kill it, otherwise
#    launchd respawns it before lldb starts waiting and --wait-for never fires.
#    `pkill lldb` matches by exec name, so it kills the lldb children of any
#    `sudo lldb` wrappers; their sudo parents exit when the child dies.) ────
sudo pkill -9 lldb 2>/dev/null || true
pkill -9 FindMy 2>/dev/null || true
sleep 0.5

# ── Prepare output directory ─────────────────────────────────────────────
# Every key from the previous run must actually be gone before we start. If one
# survives, the wait loop below sees three files on its first iteration, breaks
# immediately, and the run reports success having captured nothing — and the
# verification step passes too, because Find My keys are stable across reboots,
# so last month's key still decrypts today's cache. Three green ticks, no
# extraction. Deleting a file needs write permission on the *directory*, so this
# happens whenever keys/ is left owned by root, which is what older versions of
# this script did before they chowned what they wrote.
mkdir -p "$KEYS_DIR"
rm -f "$KEYS_DIR"/LocalStorage.key
rm -f "$KEYS_DIR"/LocalStorage.key.candidate
rm -f "$KEYS_DIR"/*.bplist
rm -f "$FINDMY_TMP_DIR"/*.bplist 2>/dev/null || true

STALE=""
for f in "$KEYS_DIR"/LocalStorage.key "$KEYS_DIR"/LocalStorage.key.candidate "$KEYS_DIR"/*.bplist; do
    [ -e "$f" ] && STALE="$STALE  $f\n"
done
if [ -n "$STALE" ]; then
    echo ""
    echo "  ❌  Could not clear the previous run's keys from ./keys/"
    echo ""
    printf "%b" "$STALE"
    echo "      Owner of ./keys/: $(stat -f %Su "$KEYS_DIR")   you: $(whoami)"
    echo ""
    echo "      Removing a file needs write permission on the directory that"
    echo "      holds it, so a keys/ owned by root cannot be cleared by you."
    echo "      Left alone, this run would find those files still in place,"
    echo "      stop immediately, and report success without extracting"
    echo "      anything — old keys still verify, because Find My keys do not"
    echo "      change across reboots."
    echo ""
    echo "      Fix it with:  sudo chown -R $(whoami) $KEYS_DIR"
    echo ""
    exit 1
fi

# ── Launch both lldb sessions in parallel — they enter --wait-for state ───
# Several `process continue` commands, not one. lldb runs -o commands in order
# and `process continue` returns when the process stops, so each queued one
# absorbs a stop that would otherwise end the session — a simultaneous
# multi-thread breakpoint hit, or a breakpoint condition that errors. That is
# the single mechanism behind every capture loss seen so far: batch-mode lldb
# quits the instant it sees a stop with nothing left to run. Extras are harmless
# once the target is gone; extract.sh kills these sessions itself regardless.
# The locateagent session is armed through a function because it may need to be
# armed more than once. `lldb --wait-for` attaches to the next process with this
# name that launches — which is not necessarily the one we are about to start.
# The agent is launchd-managed with KeepAlive, so it can respawn on its own in
# the window between arming lldb and running kickstart; lldb then attaches to
# that instance, `kickstart -k` terminates it, and the session is left holding a
# corpse with its breakpoint never resolved. Seen once in twenty runs: the log
# shows `resolved 0 locations`, then SIGTERM during dyld, and no key.
arm_locateagent() {
    sudo lldb --wait-for -n findmylocateagent \
        -o "settings set frame-format ''" \
        -o "settings set auto-confirm true" \
        -o "command script import $SCRIPT_DIR/extract_db_key.py" \
        -o "process continue" \
        -o "process continue" \
        -o "process continue" \
        -o "process continue" \
        -o "process continue" >> "$LOG1" 2>&1 &
    PID1=$!
}
: > "$LOG1"
arm_locateagent

# EXPERIMENT: the FindMy side is armed through a function so the app can be
# relaunched mid-run. Measured on an M4 Max over 40 runs, the dominant failure
# is not a capture that goes wrong — it is Find My never asking the keychain for
# a key at all: 6 runs in 20 skipped one or both reads, interspersed with clean
# ones. No key has ever arrived later than 22s, and never after the 30s mark, so
# waiting cannot recover it. A fresh launch can.
arm_findmy() {
    sudo lldb --wait-for -n FindMy \
        -o "settings set frame-format ''" \
        -o "settings set auto-confirm true" \
        -o "command script import $SCRIPT_DIR/extract_keychain_keys.py" \
        -o "process continue" \
        -o "process continue" \
        -o "process continue" \
        -o "process continue" \
        -o "process continue" >> "$LOG2" 2>&1 &
    PID2=$!
}
: > "$LOG2"
arm_findmy

# ── Give the lldb waiters a moment to install themselves ──────────────────
sleep 1

# ── NOW restart findmylocateagent via launchctl — `pkill -9` is unreliable
#    here (the daemon survives SIGKILL on some configurations, possibly due
#    to launchd protection or a stuck-zombie state). `kickstart -k` cleanly
#    stops and restarts via launchd's own mechanism so the waiting lldb
#    catches the fresh PID. The agent runs in the per-user GUI domain. ────
USER_UID=$(id -u "$(stat -f %Su /dev/console)")
kick_locateagent() {
    sudo launchctl kickstart -k "gui/$USER_UID/com.apple.findmy.findmylocateagent" 2>/dev/null || true
}
kick_locateagent
sleep 1

launch_findmy() {
    open /System/Applications/FindMy.app
    LAST_LAUNCH_AT="${ELAPSED:-0}"
}
launch_findmy

# Reads of one keychain item since the last relaunch, i.e. during the current
# attempt. index() rather than a regex so the bracketed name needs no escaping.
reads_this_attempt() {
    awk -v n="$1" '
        /──── relaunch ────/          { c = 0 }
        index($0, "SecItemCopyMatching [" n "]") { c++ }
        END                           { print c + 0 }
    ' "$LOG2" 2>/dev/null || echo 0
}

relaunch_findmy() {
    pkill -9 FindMy 2>/dev/null || true
    sleep 0.5
    echo "" >> "$LOG2"
    echo "──── relaunch ────" >> "$LOG2"
    arm_findmy
    sleep 1
    launch_findmy
}

# ── Wait for keys (scripts kill targets when done) ────────────────────────
# Budget in seconds, not a fixed iteration count, because a relaunch has to be
# able to extend it. Relaunching to recover a missing read is pointless if the
# relaunch spends the time the fresh attempt needs: measured at --wait 45 with
# three relaunches, the last attempt got its keychain read one line before the
# window closed and the run ended before the return could fire. The remedy was
# starving itself, and the failure looked like a capture defect.
BUDGET="$WAIT_SECONDS"
while [ "$ELAPSED" -lt "$BUDGET" ]; do
    # Copy any FMF/FMIP bplists out of FindMy's sandbox container as soon
    # as they show up (extract_keychain_keys.py can't write $KEYS_DIR
    # directly from inside the sandboxed process).
    for NAME in FMFDataManager FMIPDataManager; do
        SRC="$FINDMY_TMP_DIR/$NAME.bplist"
        DST="$KEYS_DIR/$NAME.bplist"
        if [ -f "$SRC" ] && [ ! -f "$DST" ]; then
            # A silent `cp` here cost a full test cycle: the capture succeeded,
            # the file was written into the sandbox with an unreadable mode, and
            # the copy failed with its error discarded — so the run looked like
            # the capture had never fired at all. Report it, and try to recover
            # by fixing the mode, since the file belongs to us either way.
            if ! cp "$SRC" "$DST" 2>/dev/null; then
                chmod u+r "$SRC" 2>/dev/null || true
                if ! cp "$SRC" "$DST" 2>/dev/null; then
                    echo ""
                    echo "  ⚠️  captured $NAME.bplist but could not copy it out of"
                    echo "      FindMy's container: $(stat -f 'mode=%Sp owner=%Su' "$SRC" 2>/dev/null)"
                fi
            fi
        fi
    done

    ELAPSED=$((ELAPSED + 1))
    got=0
    M_LS="·"; M_FMF="·"; M_FMIP="·"
    if [ -f "$KEYS_DIR/LocalStorage.key" ] || [ -f "$KEYS_DIR/LocalStorage.key.candidate" ]; then
        got=$((got+1)); M_LS="✅"
    fi
    [ -f "$KEYS_DIR/FMFDataManager.bplist" ]  && { got=$((got+1)); M_FMF="✅"; }
    [ -f "$KEYS_DIR/FMIPDataManager.bplist" ] && { got=$((got+1)); M_FMIP="✅"; }

    # Live progress: a 3-minute wait with no output looks like a hang. Update in
    # place on a terminal; print a periodic line when redirected to a file.
    STATUS="LocalStorage $M_LS   FMF $M_FMF   FMIP $M_FMIP"
    if [ -t 1 ]; then
        printf '\r      %3ds  %s ' "$ELAPSED" "$STATUS"
    elif [ $((ELAPSED % 30)) -eq 0 ]; then
        echo "      ${ELAPSED}s  $STATUS"
    fi

    if [ "$got" -ge 3 ]; then
        [ -t 1 ] && printf '\r\033[2K' 
        break
    fi
    # Stop as soon as the outcome is known, rather than serving out the clock.
    # Each lldb session owns specific keys — PID1 the LocalStorage key, PID2 the
    # two keychain bplists — and a session exits once it has finished, whether or
    # not it captured anything. So a dead session with its keys still missing is
    # a settled failure, and waiting past it just hides which half went wrong
    # behind a timeout message that blames slow hardware.
    # One more copy attempt first: a session can exit in the window between this
    # iteration's copy pass and the check below, and a bplist sitting in the
    # sandbox uncopied must not be read as a failed capture.
    for NAME in FMFDataManager FMIPDataManager; do
        if [ -f "$FINDMY_TMP_DIR/$NAME.bplist" ] && [ ! -f "$KEYS_DIR/$NAME.bplist" ]; then
            chmod u+r "$FINDMY_TMP_DIR/$NAME.bplist" 2>/dev/null || true
            cp "$FINDMY_TMP_DIR/$NAME.bplist" "$KEYS_DIR/$NAME.bplist" 2>/dev/null || true
        fi
    done

    LS_PENDING=0; KC_PENDING=0
    [ ! -f "$KEYS_DIR/LocalStorage.key" ] && [ ! -f "$KEYS_DIR/LocalStorage.key.candidate" ] && LS_PENDING=1
    { [ ! -f "$KEYS_DIR/FMFDataManager.bplist" ] || [ ! -f "$KEYS_DIR/FMIPDataManager.bplist" ]; } && KC_PENDING=1

    P1_DEAD=0; kill -0 "$PID1" 2>/dev/null || P1_DEAD=1
    P2_DEAD=0; kill -0 "$PID2" 2>/dev/null || P2_DEAD=1

    if [ "$P1_DEAD" = "1" ] && [ "$LS_PENDING" = "1" ]; then
        # A dead session with no key is usually the wrong-instance attach above,
        # which a second attempt clears — the agent is still there to be
        # restarted. Retry rather than spend the rest of the window on a session
        # that is already gone. Bounded, and it logs every attempt.
        if [ "${LOCATE_RETRIES:-0}" -gt 0 ]; then
            LOCATE_RETRIES=$((LOCATE_RETRIES - 1))
            [ -t 1 ] && printf '\r\033[2K'
            echo "  ↻  the findmylocateagent session ended without the key after"
            echo "      ${ELAPSED}s — reattaching and restarting the agent"
            echo "" >> "$LOG1"
            echo "──── retry ────" >> "$LOG1"
            arm_locateagent
            sleep 1
            kick_locateagent
        elif [ -z "${SAID_LS:-}" ]; then
            SAID_LS=1
            [ -t 1 ] && printf '\r\033[2K'
            echo "  ⚠️  the findmylocateagent session ended after ${ELAPSED}s without"
            echo "      capturing LocalStorage.key — see ./logs/lldb_locateagent.log"
        fi
    fi
    if [ "$P2_DEAD" = "1" ] && [ "$KC_PENDING" = "1" ] && [ -z "${SAID_KC:-}" ]; then
        SAID_KC=1
        [ -t 1 ] && printf '\r\033[2K'
        echo "  ⚠️  the FindMy session ended after ${ELAPSED}s without capturing"
        echo "      both keychain keys — see ./logs/lldb_findmy.log"
    fi

    # EXPERIMENT: relaunch Find My when a key was never requested.
    #
    # The trigger is anchored to the first read actually happening, not to the
    # clock, because how long Find My takes to get there is exactly what varies
    # between an M4 Max and a VM — a fixed deadline would relaunch a slow
    # machine that was about to succeed. Once one read has landed, though, the
    # other belongs to the same startup sequence: in every observed case they
    # arrived within a second of each other, or the second never came at all.
    # So a grace period after the first read is a hardware-independent signal
    # that the second is not coming.
    #
    # The both-missing case has no first read to anchor to, so it falls back to
    # the clock, at half the wait budget — still generous against the 22s
    # worst-case observed here, and it only costs a slow machine one relaunch.
    if [ "$KC_PENDING" = "1" ] && [ "${FINDMY_RELAUNCHES:-0}" -gt 0 ]; then
        # Reads *since the last relaunch*, not since the run started. A plain
        # grep -c would still see the previous attempt's read, set the anchor
        # immediately, and fire the next relaunch a grace period later without
        # the new launch ever having been given a chance.
        READS_NOW=$(awk '/──── relaunch ────/{n=0} /SecItemCopyMatching \[/{n++} END{print n+0}' "$LOG2" 2>/dev/null || echo 0)
        if [ "${READS_NOW:-0}" -gt 0 ] && [ -z "${FIRST_READ_AT:-}" ]; then
            FIRST_READ_AT="$ELAPSED"
        fi

        RELAUNCH=0
        if [ -n "${FIRST_READ_AT:-}" ]; then
            [ $((ELAPSED - FIRST_READ_AT)) -ge "$READ_GRACE" ] && RELAUNCH=1
        elif [ $((ELAPSED - ${LAST_LAUNCH_AT:-0})) -ge $((WAIT_SECONDS / 2)) ]; then
            RELAUNCH=1
        fi

        # Never relaunch a key that Find My *did* ask for. This mechanism exists
        # for one failure — the read never arriving — and relaunching is a
        # `pkill -9`. Once the read has landed the capture is either in flight or
        # has failed, and killing the process helps neither: it lands in the
        # window between the read and the capture completing, and destroys a
        # capture that was about to succeed. Measured doing exactly that.
        #
        # That window is wider when the handler runs through lldb's command
        # interpreter than when it is a synchronous breakpoint condition, so the
        # misfire is not evenly distributed across capture designs — which is
        # how it corrupted a comparison between two of them.
        # Hold off relaunching only while a capture could still be in flight —
        # a few seconds after a read — rather than for the rest of the run.
        #
        # The first version of this blocked permanently on any read, which was
        # too blunt in both directions. It was global, so a read for one key
        # blocked the remedy for the other; and it never expired, so a capture
        # that had demonstrably failed still suppressed the relaunch that could
        # have recovered it. Measured cost: 4 runs in 9 had a remedy available
        # and did not use it, and it turned a 7/10 into a 6/10.
        #
        # Relaunching *does* recover failed captures, not just missing reads —
        # one run captured FMIP on the third read after two relaunches. The only
        # thing worth protecting is the brief window where the read has landed
        # and the handler has not finished, which is what killed a capture and
        # corrupted a comparison earlier.
        if [ "$RELAUNCH" = "1" ]; then
            NEWEST_READ=-999
            for NAME in FMFDataManager FMIPDataManager; do
                [ -f "$KEYS_DIR/$NAME.bplist" ] && continue
                N=$(reads_this_attempt "$NAME")
                [ "$N" -eq 0 ] && continue
                eval "PREV=\${SEEN_${NAME}:-0}"
                if [ "$N" -ne "$PREV" ]; then
                    eval "SEEN_${NAME}=$N"
                    eval "AT_${NAME}=$ELAPSED"
                fi
                eval "AT=\${AT_${NAME}:-$ELAPSED}"
                [ "$AT" -gt "$NEWEST_READ" ] && NEWEST_READ="$AT"
            done

            if [ "$NEWEST_READ" -gt -999 ] &&
               [ $((ELAPSED - NEWEST_READ)) -lt "$CAPTURE_SETTLE" ]; then
                RELAUNCH=0
                if [ -z "${SAID_INFLIGHT:-}" ]; then
                    SAID_INFLIGHT=1
                    [ -t 1 ] && printf '\r\033[2K'
                    echo "  …  a keychain read landed $((ELAPSED - NEWEST_READ))s ago —"
                    echo "      holding off the relaunch until the capture settles"
                fi
            fi
        fi

        if [ "$RELAUNCH" = "1" ]; then
            FINDMY_RELAUNCHES=$((FINDMY_RELAUNCHES - 1))
            [ -t 1 ] && printf '\r\033[2K'
            MISSING=""
            for NAME in FMFDataManager FMIPDataManager; do
                [ -f "$KEYS_DIR/$NAME.bplist" ] || MISSING="$MISSING $NAME"
            done
            echo "  ↻  Find My did not ask for:$MISSING — relaunching it"
            unset FIRST_READ_AT
            relaunch_findmy
            ELAPSED=$((ELAPSED + 2))
            # Grant the fresh attempt its own time rather than billing it to
            # what is left. Capped so a pathological run still terminates.
            BUDGET=$((BUDGET + ATTEMPT_BUDGET))
            [ "$BUDGET" -gt $((WAIT_SECONDS * 3)) ] && BUDGET=$((WAIT_SECONDS * 3))
            continue
        fi
    fi

    # Nothing left that could still arrive.
    if { [ "$P1_DEAD" = "1" ] || [ "$LS_PENDING" = "0" ]; } &&
       { [ "$P2_DEAD" = "1" ] || [ "$KC_PENDING" = "0" ]; }; then
        [ -t 1 ] && printf '\r\033[2K'
        break
    fi
    sleep 1
done

[ -t 1 ] && printf '\r\033[2K' 

# Drop the lldb sessions from the job table before killing them. Otherwise bash
# announces the reap itself — "line N: 1234 Killed: 9  sudo lldb --wait-for …" —
# which looks like an error to the user and is nothing of the kind. `wait` can't
# be used on a disowned job, so poll for exit instead.
disown "$PID1" "$PID2" 2>/dev/null || true
sudo kill -9 "$PID1" "$PID2" 2>/dev/null || true
for _ in $(seq 1 15); do
    if ! kill -0 "$PID1" 2>/dev/null && ! kill -0 "$PID2" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

# One last copy pass in case a bplist landed in the sandbox tmp dir right
# as the loop above exited.
for NAME in FMFDataManager FMIPDataManager; do
    SRC="$FINDMY_TMP_DIR/$NAME.bplist"
    DST="$KEYS_DIR/$NAME.bplist"
    if [ -f "$SRC" ] && [ ! -f "$DST" ]; then
        # Last chance to recover a capture — same silent-cp trap as above.
        if ! cp "$SRC" "$DST" 2>/dev/null; then
            chmod u+r "$SRC" 2>/dev/null || true
            if ! cp "$SRC" "$DST" 2>/dev/null; then
                echo ""
                echo "  ⚠️  captured $NAME.bplist but could not copy it out of"
                echo "      FindMy's container: $(stat -f 'mode=%Sp owner=%Su' "$SRC" 2>/dev/null)"
            fi
        fi
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
    # What failed, before why it failed. This runs whether or not the logs
    # hold an error: an error explains a capture that broke, but says nothing
    # about a key that was never requested, and both can happen in one run. Every
    # intercepted read is logged, so a key with zero reads was never asked
    # for by Find My and no wait length can produce it. Report per key: the
    # usual failure is partial (one key read, the other not), and a blanket
    # "try a longer wait" sends people to chase hardware that did nothing
    # wrong. Measured on an M4 Max: 6 runs in 14 skipped one or both reads,
    # interspersed with clean runs, and it recovers on its own.
    for NAME in FMFDataManager FMIPDataManager; do
        [ -f "$KEYS_DIR/$NAME.bplist" ] && continue
        N=$(grep -c "SecItemCopyMatching \[$NAME\]" "$LOG2" 2>/dev/null || echo 0)
        if [ "${N:-0}" -eq 0 ]; then
            echo "  $NAME.bplist — Find My never asked the keychain for this"
            echo "      key, so there was nothing to intercept. Run the extractor"
            echo "      again in a minute; this clears on its own."
        else
            echo "  $NAME.bplist — Find My read this key $N time(s) but it was"
            echo "      not captured. See ./logs/lldb_findmy.log"
        fi
    done

    if [ ! -f "$KEYS_DIR/LocalStorage.key" ]; then
        if grep -q "sqlite3_key_v2 hit" "$LOG1" 2>/dev/null; then
            echo "  LocalStorage.key — findmylocateagent opened a database but the"
            echo "      session ended before LocalStorage.db was reached."
            echo "      See ./logs/lldb_locateagent.log"
        else
            echo "  LocalStorage.key — findmylocateagent never opened an encrypted"
            echo "      database during this run. Run the extractor again."
        fi
    fi

    FOUND=$(grep -hE '⚠️|❌|Traceback|Error|error:|KeyError|Exception|RuntimeError|failed' \
        "$LOG1" "$LOG2" 2>/dev/null | grep -v "^  *$" | tail -30 || true)
    if [ -n "$FOUND" ]; then
        echo ""
        echo "  From the lldb logs:"
        printf '%s\n' "$FOUND"
    fi
fi

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "  💾 Saved to ./keys/"
fi

echo ""
