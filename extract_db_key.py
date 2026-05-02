"""
extract_db_key.py — lldb script to extract the AES-256 key for LocalStorage.db.

Sets a breakpoint on sqlite3_key_v2 in findmylocateagent. On each hit,
identifies the database via sqlite3_db_filename. When LocalStorage is found,
saves the 32-byte key and kills the process (launchd respawns it).

Usage:
  sudo lldb --wait-for -n findmylocateagent \
    -o "command script import extract_db_key.py" \
    -o "c" -o "quit"

Keys are written to disk only — never printed to terminal.
"""

import lldb
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "keys"
KEY_FILE = OUT_DIR / "LocalStorage.key"

_done = False
_bp = None


def _log(msg):
    print(msg, flush=True)


def _is_x86(frame):
    triple = frame.GetThread().GetProcess().GetTarget().GetTriple() or ""
    return triple.startswith("x86_64")


def _arg(frame, n):
    """n-th integer/pointer argument under the platform C ABI."""
    names = (["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if _is_x86(frame)
             else ["x0", "x1", "x2", "x3", "x4", "x5"])
    return frame.FindRegister(names[n]).GetValueAsUnsigned()


def _read_mem(process, ptr, size):
    if not ptr or size <= 0 or size > 65536:
        return None
    err = lldb.SBError()
    data = process.ReadMemory(int(ptr), int(size), err)
    return bytes(data) if err.Success() else None


def _get_db_path(frame, db_ptr):
    """Get the DB filename via sqlite3_db_filename expression eval."""
    if _bp and _bp.IsValid():
        _bp.SetEnabled(False)

    opts = lldb.SBExpressionOptions()
    opts.SetTimeoutInMicroSeconds(5_000_000)
    opts.SetTryAllThreads(False)
    result = frame.EvaluateExpression(
        f'(char*)sqlite3_db_filename((void*){db_ptr}, "main")', opts
    )

    if _bp and _bp.IsValid():
        _bp.SetEnabled(True)

    if result.GetError().Fail():
        return None
    ptr = result.GetValueAsUnsigned()
    if not ptr:
        return None
    data = _read_mem(frame.GetThread().GetProcess(), ptr, 512)
    if not data:
        return None
    return data.split(b"\x00")[0].decode("utf-8", errors="replace")


def on_sqlite3_key_v2(frame, bp_loc, extra_args, internal_dict):
    global _done
    if _done:
        return False

    process = frame.GetThread().GetProcess()
    db_ptr  = _arg(frame, 0)
    key_ptr = _arg(frame, 2)
    key_len = _arg(frame, 3)
    _log(f"  🔔  sqlite3_key_v2 hit: db=0x{db_ptr:x} key=0x{key_ptr:x} len={key_len}")

    if key_len != 32:
        return False

    db_path = _get_db_path(frame, db_ptr)
    if not db_path or "LocalStorage" not in db_path:
        return False

    key_data = _read_mem(process, key_ptr, 32)
    if not key_data:
        _log("  ❌  Failed to read key from memory")
        return False

    with open(KEY_FILE, "wb") as f:
        f.write(key_data)

    _done = True
    _log(f"  ✅  Captured LocalStorage key → {KEY_FILE.name}")
    process.Kill()
    return False


def __lldb_init_module(debugger, internal_dict):
    global _bp

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        _log("  ❌  No valid target")
        return

    triple = target.GetTriple() or "(unknown)"
    _log(f"  📍  target triple: {triple}")

    _bp = target.BreakpointCreateByName("sqlite3_key_v2")
    _bp.SetScriptCallbackFunction("extract_db_key.on_sqlite3_key_v2")
    _log(f"  ⏳  Intercepting sqlite3_key_v2 (resolved {_bp.GetNumLocations()} locations)")
