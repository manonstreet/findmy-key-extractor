"""
extract_key.py — lldb script to extract the AES-256 key for LocalStorage.db.

Sets a breakpoint on sqlite3_key_v2 in findmylocateagent. On each hit,
tries to identify the database via sqlite3_db_filename. Saves the
LocalStorage key to ~/FindMySyncPlus/setup/localstorage.key (32 raw bytes),
then detaches cleanly.

Fallback: if sqlite3_db_filename fails, saves keys as key_1.bin / key_2.bin
for later verification.

Usage:
  sudo lldb -p $(pgrep findmylocateagent) \
    -o "command script import extract_key.py" \
    -o "c"
  Then open Find My app to trigger key derivation.

Keys are written to disk only — never printed to terminal.
"""

import lldb
import time
from pathlib import Path

OUT_DIR = Path.home() / "FindMySyncPlus" / "setup"
OUT_DIR.mkdir(parents=True, exist_ok=True)

KEY_FILE = OUT_DIR / "localstorage.key"

_st = {
    "hit_count": 0,
    "identified": False,   # True once we've saved the LocalStorage key by name
    "fallback_keys": [],   # list of (index, bytes) for fallback mode
    "done": False,
}


def _log(msg):
    print(msg, flush=True)


def _read_mem(process, ptr, size):
    if not ptr or size <= 0 or size > 65536:
        return None
    err = lldb.SBError()
    data = process.ReadMemory(int(ptr), int(size), err)
    return bytes(data) if err.Success() else None


def _save(path, data):
    with open(path, "wb") as f:
        f.write(data)
    _log(f"  -> saved {path.name} ({len(data)} bytes)")


def _detach(process):
    _st["done"] = True
    _log("\nDetaching from process...")
    process.Detach()
    _log("Done. Process continues running.")


def _try_db_filename(frame, db_ptr):
    """Try to get the DB filename via sqlite3_db_filename expression eval."""
    opts = lldb.SBExpressionOptions()
    opts.SetTimeoutInMicroSeconds(5_000_000)
    opts.SetTryAllThreads(False)
    result = frame.EvaluateExpression(
        f'(char*)sqlite3_db_filename((void*){db_ptr}, "main")', opts
    )
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
    if _st["done"]:
        return False

    _st["hit_count"] += 1
    n = _st["hit_count"]

    process = frame.GetThread().GetProcess()
    db_ptr  = frame.FindRegister("x0").GetValueAsUnsigned()
    key_ptr = frame.FindRegister("x2").GetValueAsUnsigned()
    key_len = frame.FindRegister("x3").GetValueAsUnsigned()

    _log(f"\n[sqlite3_key_v2 #{n}] dbPtr={hex(db_ptr)} keyLen={key_len}")

    if key_len != 32:
        _log(f"  unexpected key length {key_len}, skipping")
        return False

    key_data = _read_mem(process, key_ptr, 32)
    if not key_data:
        _log("  failed to read key from memory, skipping")
        return False

    # Try to identify the database
    db_path = _try_db_filename(frame, db_ptr)
    if db_path:
        _log(f"  db path: ...{db_path[-60:]}" if len(db_path) > 60 else f"  db path: {db_path}")

        if "LocalStorage" in db_path:
            _log("  -> LocalStorage key identified!")
            _save(KEY_FILE, key_data)
            _st["identified"] = True
            _detach(process)
            return False
        else:
            _log("  (not LocalStorage, continuing)")
    else:
        _log("  db_filename eval failed, using fallback mode")
        fallback_path = OUT_DIR / f"key_{n}.bin"
        _save(fallback_path, key_data)
        _st["fallback_keys"].append((n, key_data))

    # After 2 hits, if we haven't identified the key, detach with fallback keys
    if _st["hit_count"] >= 2 and not _st["identified"]:
        _log("\n  2 keys captured in fallback mode.")
        _log("  Run verify_key.py to determine which is correct.")
        _detach(process)

    return False


def __lldb_init_module(debugger, internal_dict):
    _log("extract_key: setting up breakpoint on sqlite3_key_v2...")

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        _log("ERROR: no valid target")
        return

    bp = target.BreakpointCreateByName("sqlite3_key_v2")
    bp.SetScriptCallbackFunction("extract_key.on_sqlite3_key_v2")

    status = "OK" if bp.IsValid() and bp.GetNumLocations() > 0 else "NOT FOUND"
    _log(f"  BP {bp.GetID()}: sqlite3_key_v2 [{status}] locs={bp.GetNumLocations()}")
    _log(f"\nOutput directory: {OUT_DIR}")
    _log("Waiting for findmylocateagent to open databases...")
    _log("Open Find My app now to trigger key derivation.\n")
