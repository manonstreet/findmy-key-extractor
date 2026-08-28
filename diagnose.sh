#!/bin/bash
# Environment report for FindMySyncPlus / findmy-key-extractor issues.
#
# Run this, paste the whole output into your GitHub issue. It answers the
# questions we would otherwise have to ask one at a time.
#
# Safe to paste publicly: no key material, no device names, no Apple ID, and
# your username is replaced with <user> throughout. Read-only — it changes
# nothing and needs no sudo.

set -uo pipefail

USER_NAME="$(id -un)"
scrub() {
    sed -e "s|$HOME|~|g" \
        -e "s|/Users/$USER_NAME|/Users/<user>|g" \
        -e "s|\b$USER_NAME\b|<user>|g" \
        -e "s|/var/folders/[^/]*/[^/]*/|/var/folders/<darwin>/|g" \
        -e "s|/private/var/folders/[^/]*/[^/]*/|/var/folders/<darwin>/|g"
}

say() { printf '%s\n' "$*"; }
hdr() { printf '\n── %s ──\n' "$*"; }

BLOCKERS=()
say "FindMySync+ / key-extractor diagnostics — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ── System ────────────────────────────────────────────────────────────────
hdr "System"
say "  macOS:  $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
say "  arch:   $(uname -m)"
say "  model:  $(sysctl -n hw.model 2>/dev/null)"

VM="no"
ioreg -l 2>/dev/null | grep -qiE "vmware|parallels|virtualbox|qemu|innotek" && VM="yes"
case "$(sysctl -n hw.model 2>/dev/null)" in VMware*|Parallels*|VirtualBox*) VM="yes";; esac
say "  VM:     $VM"

OCLP="no"
[ -d "/Library/Application Support/Dortania" ] && OCLP="yes"
[ -d "/Applications/OpenCore-Patcher.app" ] && OCLP="yes"
say "  OCLP:   $OCLP"

# ── Extraction prerequisites ──────────────────────────────────────────────
hdr "SIP / AMFI (extractor prerequisites)"
csrutil status 2>/dev/null | sed 's/^/  /' | head -12
say "  kern.bootargs: $(sysctl -n kern.bootargs 2>/dev/null || echo '(none)')"
if csrutil status 2>/dev/null | grep -qiE "Debugging Restrictions: enabled|status: enabled"; then
    BLOCKERS+=("SIP debugging restrictions still enabled — needs a full 'csrutil disable' (README Step 1)")
fi

# Decode the SIP bitmask and check the one bit this tool actually needs.
# ALLOW_TASK_FOR_PID (0x4) is the requirement: without it lldb cannot attach and
# nothing else matters. Intel keeps the value in NVRAM; Apple Silicon keeps it in
# the boot policy where only bputil (root) can read it.
_csr_raw=$(nvram csr-active-config 2>/dev/null | awk '{print $2}')
if [ -n "${_csr_raw:-}" ]; then
    # nvram prints it byte-swapped as %xx escapes, e.g. %ff%0f -> 0x0fff
    _hex=$(printf '%s' "$_csr_raw" | tr -d '%' | sed 's/\(..\)\(..\)/\2\1/')
    _val=$((16#${_hex:-0}))
    say "  csr-active-config: $_csr_raw  = 0x$(printf '%x' $_val)"
    # Reported, not asserted. Every configuration this tool has been verified on
    # was a full `csrutil disable`. Which individual bits are strictly required
    # has never been tested, so a partial config is reported as untested rather
    # than declared broken.
    if [ $(( _val & 4 )) -ne 0 ]; then
        say "  ALLOW_TASK_FOR_PID: set"
    else
        say "  ALLOW_TASK_FOR_PID: not set — lldb attach is expected to fail"
        BLOCKERS+=("SIP does not allow task_for_pid (0x4), which lldb needs to attach. Note: this tool is only verified against a full 'csrutil disable' — partial configurations are untested either way")
    fi
    _flags=""
    for f in "1:UNTRUSTED_KEXTS" "2:UNRESTRICTED_FS" "4:TASK_FOR_PID" \
             "8:KERNEL_DEBUGGER" "16:APPLE_INTERNAL" "32:UNRESTRICTED_DTRACE" \
             "64:UNRESTRICTED_NVRAM" "128:DEVICE_CONFIGURATION" \
             "256:ANY_RECOVERY_OS" "512:UNAPPROVED_KEXTS" \
             "1024:EXECUTABLE_POLICY_OVERRIDE" "2048:UNAUTHENTICATED_ROOT"; do
        [ $(( _val & ${f%%:*} )) -ne 0 ] && _flags="$_flags ${f##*:}"
    done
    say "  allowed:${_flags:- none}"
    csrutil status 2>/dev/null | grep -qi "status: disabled" || \
        say "  note: verified configurations are a full 'csrutil disable'; this is partial"
elif [ "$(uname -m)" = "arm64" ]; then
    say "  csr-active-config: not in NVRAM (Apple Silicon keeps SIP in the boot policy)"
    # The boot policy is what decides whether the AMFI boot-arg is honoured, and
    # only bputil can read it. csrutil reports "disabled" for a config bputil
    # calls "Customized (sip0): 7f" — same state, different wording, so csrutil
    # alone cannot answer this.
    BP=$(sudo bputil -d 2>/dev/null || true)
    if [ -n "$BP" ]; then
        BP_MODE=$(printf '%s' "$BP" | sed -n 's/^Security Mode: *\([A-Za-z]*\).*/\1/p')
        BP_SIP=$(printf '%s' "$BP" | sed -n 's/^SIP Status: *[A-Za-z]* *(sip0): *\(.*\)$/\1/p')
        BP_FILT=$(printf '%s' "$BP" | sed -n 's/^Boot Args Filtering Status: *\([A-Za-z]*\).*/\1/p')
        say "  Security Mode:              ${BP_MODE:-?}   (needs Permissive)"
        say "  SIP word (sip0):            ${BP_SIP:-?}   (7f is a FULL disable here)"
        say "  Boot Args Filtering Status: ${BP_FILT:-?}   (needs Disabled)"
        if [ "$BP_MODE" != "Permissive" ] || [ "$BP_FILT" != "Disabled" ]; then
            BLOCKERS+=("The AMFI boot argument will not take effect. On Apple Silicon boot args are only honoured under Permissive Security with boot-args filtering disabled — until then amfi_get_out_of_my_way=1 appears in kern.bootargs while AMFI keeps enforcing, and every memory read in the debugger fails")
        fi
    else
        say "  boot policy: could not read it — run 'sudo bputil -d' and include"
        say "               the output. Security Mode and Boot Args Filtering are"
        say "               what decide whether the AMFI boot-arg is honoured."
    fi
fi

# Accept every form in the wild: =1, =0x1, and OCLP's amfi=0x80.
if sysctl -n kern.bootargs 2>/dev/null | grep -qE "amfi_get_out_of_my_way=(1|0x1)|amfi=0x80"; then
    say "  AMFI: disabled ✅"
else
    say "  AMFI: NOT disabled ❌  — extraction will fail; see README Step 1"
    BLOCKERS+=("AMFI is not disabled — add amfi_get_out_of_my_way=1 to boot-args. On OpenCore/OCLP machines the app's 'Disable AMFI' checkbox may not emit a boot-arg; set it with sudo nvram, or via the Advanced tab, then reboot")
fi

hdr "Toolchain"
say "  lldb:   $(lldb --version 2>/dev/null | head -1 || echo 'not installed')"
say "  xcode-select: $(xcode-select -p 2>/dev/null)"
# Prefer the venv beside the script, exactly as extract.sh does — otherwise this
# reports "deps missing" on a machine where --setup has already succeeded.
# $0 is unreliable when this is piped (curl | bash, ssh 'bash -s'), so try the
# script's directory and the working directory.
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "$PWD")"
PY=""
for cand in "$HERE/.venv/bin/python3" "$PWD/.venv/bin/python3"; do
    [ -x "$cand" ] && { PY="$cand"; break; }
done
if [ -n "$PY" ]; then
    say "  python3: .venv/bin/python3 ($("$PY" -V 2>&1))"
else
    PY="$(command -v python3 || echo none)"
    say "  python3: $PY ($($PY -V 2>&1))  [no .venv present]"
fi
if "$PY" -c "import Crypto, cryptography" 2>/dev/null; then
    say "  deps:   present ✅"
else
    say "  deps:   MISSING ❌  — run ./extract.sh --setup"
    BLOCKERS+=("Python dependencies missing — run ./extract.sh --setup")
fi

# ── iCloud / Find My ──────────────────────────────────────────────────────
hdr "iCloud / Find My"
if defaults read MobileMeAccounts 2>/dev/null | grep -q AccountID; then
    say "  signed in: yes"
    defaults read MobileMeAccounts 2>/dev/null | grep -qi "FIND_MY_MAC" \
        && say "  Find My Mac: provisioned" || say "  Find My Mac: NOT provisioned ❌"
else
    say "  signed in: NO ❌ — no Find My data will exist"
    BLOCKERS+=("Not signed into iCloud — there is no Find My data to read")
fi
if pgrep -qx findmylocateagent; then
    say "  findmylocateagent: running"
else
    say "  findmylocateagent: NOT running ❌"
    BLOCKERS+=("findmylocateagent is not running — open the Find My app once")
fi

# ── The FMIP caches (devices + items) ─────────────────────────────────────
hdr "FMIP caches — devices and items"
FMIP="$HOME/Library/Caches/com.apple.findmy.fmipcore"
if [ -d "$FMIP" ]; then
    for f in Devices.data Items.data; do
        P="$FMIP/$f"
        if [ -f "$P" ]; then
            AGE=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$P")
            SZ=$(stat -f "%z" "$P")
            # Encrypted files are an outer plist with an encryptedData key.
            # Plaintext ones parse as an array of device dicts.
            if plutil -p "$P" 2>/dev/null | head -3 | grep -q "encryptedData"; then
                KIND="ENCRYPTED"
            elif plutil -p "$P" >/dev/null 2>&1; then
                KIND="PLAINTEXT (!)"
            else
                KIND="unreadable — Full Disk Access missing?"
            fi
            say "  $f: $KIND, ${SZ}B, modified $AGE"
        else
            say "  $f: absent"
        fi
    done
else
    say "  cache directory absent — has Find My ever run?"
fi

# ── LocalStorage.db — the friends database ────────────────────────────────
hdr "LocalStorage.db — friend locations"
DUD="$(getconf DARWIN_USER_DIR 2>/dev/null)"
A="${DUD}com.apple.findmy.findmylocateagent/LocalStorage.db"
B="$HOME/Library/Group Containers/group.com.apple.findmy.findmylocateagent/Library/Application Support/LocalStorage.db"
for label in "DARWIN_USER_DIR|$A" "GroupContainers|$B"; do
    NAME="${label%%|*}"; P="${label#*|}"
    if [ -f "$P" ]; then
        SZ=$(stat -f "%z" "$P"); W=0; [ -f "$P-wal" ] && W=$(stat -f "%z" "$P-wal")
        say "  $NAME: PRESENT  db=${SZ}B wal=${W}B  born $(stat -f "%SB" -t "%Y-%m-%d" "$P")  modified $(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$P")"
    else
        say "  $NAME: absent"
    fi
done
P=$(pgrep -x findmylocateagent | head -1)
if [ -n "$P" ]; then
    # -F n gives one field per line, so paths containing spaces survive intact
    # (the Group Containers path has "Application Support" in it).
    OPEN=$(lsof -nP -p "$P" -F n 2>/dev/null | sed -n 's/^n//p' | grep '/LocalStorage\.db$' | head -1)
    [ -n "$OPEN" ] && say "  live handle: $(printf '%s' "$OPEN" | scrub)" || say "  live handle: none reported"
fi

# ── searchpartyd (what upstream FindMySync uses on 14.4+) ─────────────────
hdr "searchpartyd (upstream FindMySync's data source on 14.4+)"
[ -d "$HOME/Library/com.apple.icloud.searchpartyd" ] \
    && say "  ~/Library/com.apple.icloud.searchpartyd: present" \
    || say "  ~/Library/com.apple.icloud.searchpartyd: absent"
[ -d "$HOME/Library/Group Containers/group.com.apple.icloud.searchpartyuseragent" ] \
    && say "  searchpartyuseragent group container: present" \
    || say "  searchpartyuseragent group container: absent"

# ── Keys — presence and size only, never contents ─────────────────────────
hdr "Extracted keys (sizes only — no key material is printed)"
K="$(cd "$(dirname "$0")" && pwd)/keys"
if [ -d "$K" ]; then
    for f in LocalStorage.key FMIPDataManager.bplist FMFDataManager.bplist; do
        [ -f "$K/$f" ] && say "  $f: $(stat -f "%z" "$K/$f")B" || say "  $f: not captured"
    done
else
    say "  no keys/ directory — extraction has not been run here"
fi

hdr "Blockers"
if [ ${#BLOCKERS[@]} -eq 0 ]; then
    say "  none detected — if extraction still fails, paste the lldb log from the run"
else
    for b in "${BLOCKERS[@]}"; do say "  ❌ $b"; done
    say ""
    say "  Fix these first — extraction cannot succeed until they are resolved."
fi

printf '\n── end ──\n' 
