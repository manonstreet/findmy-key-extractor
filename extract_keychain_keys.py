"""
extract_keychain_keys.py — lldb script to extract Find My keys via breakpoints.

Attaches to a target process and captures:
  - sqlite3_key_v2 hits → saves keys identified by sqlite3_db_filename
  - SecItemCopyMatching hits → saves all successful results with index

Works with findmylocateagent (LocalStorage.db key) and FindMy.app (FMF/FMIP keys).

Usage:
  sudo lldb --wait-for -n findmylocateagent \
    -o "command script import extract_keychain_keys.py" \
    -o "c" -o "quit"

Keys are written to disk only — never printed to terminal.
"""

import lldb
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "keys"

_bp_key_v2 = None
_bp_secitem = None
_sqlite_keys = {}   # db_name -> True (already captured)
_secitem_count = 0
_secitem_captured = 0
_secitem_resolved = 0
_pending_returns = {}
_done = False


def _log(msg):
    print(msg, flush=True)


def _read_mem(process, ptr, size):
    if not ptr or size <= 0 or size > 65536:
        return None
    err = lldb.SBError()
    data = process.ReadMemory(int(ptr), int(size), err)
    return bytes(data) if err.Success() else None


def _read_cstring(process, ptr, max_len=512):
    data = _read_mem(process, ptr, max_len)
    if not data:
        return None
    return data.split(b"\x00")[0].decode("utf-8", errors="replace")


def _finish(process):
    global _done
    if _done:
        return
    _done = True
    _log("")
    process.Kill()


# ── sqlite3_key_v2 — captures SQLite encryption keys ─────────────────────

def _on_sqlite3_key_v2(frame, bp_loc, extra_args, internal_dict):
    if _done:
        return False

    process = frame.GetThread().GetProcess()
    db_ptr  = frame.FindRegister("x0").GetValueAsUnsigned()
    key_ptr = frame.FindRegister("x2").GetValueAsUnsigned()
    key_len = frame.FindRegister("x3").GetValueAsUnsigned()

    if key_len != 32:
        return False

    # Identify the database — disable BP to prevent recursion
    if _bp_key_v2 and _bp_key_v2.IsValid():
        _bp_key_v2.SetEnabled(False)

    opts = lldb.SBExpressionOptions()
    opts.SetTimeoutInMicroSeconds(5_000_000)
    opts.SetTryAllThreads(False)
    r = frame.EvaluateExpression(
        f'(char*)sqlite3_db_filename((void*){db_ptr}, "main")', opts)

    if _bp_key_v2 and _bp_key_v2.IsValid():
        _bp_key_v2.SetEnabled(True)

    if r.GetError().Fail():
        return False

    path_ptr = r.GetValueAsUnsigned()
    db_path = _read_cstring(process, path_ptr) if path_ptr else None
    if not db_path:
        return False

    # Extract DB name from path
    db_name = db_path.rsplit("/", 1)[-1].replace(".db", "")
    if db_name in _sqlite_keys:
        return False

    key_data = _read_mem(process, key_ptr, 32)
    if not key_data:
        return False

    filename = f"{db_name}.key"
    with open(OUT_DIR / filename, "wb") as f:
        f.write(key_data)
    _sqlite_keys[db_name] = True
    _log(f"  ✅  {db_name}.key (32 bytes)")
    return False


# ── SecItemCopyMatching — capture all successful results ──────────────────

def _on_secitem_entry(frame, bp_loc, extra_args, internal_dict):
    global _secitem_count
    if _done:
        return False

    try:
        result_out_ptr = frame.FindRegister("x1").GetValueAsUnsigned()
        lr_raw = frame.FindRegister("lr").GetValueAsUnsigned()
        # Strip PAC bits (arm64e pointer authentication) — keep low 40 bits
        lr = lr_raw & 0x000000FFFFFFFFFF

        if not result_out_ptr or not lr:
            return False

        _secitem_count += 1
        idx = _secitem_count

        target = frame.GetThread().GetProcess().GetTarget()
        # Only set one BP per address — reuse if already pending
        if lr not in _pending_returns:
            bp_ret = target.BreakpointCreateByAddress(lr)
            bp_ret.SetScriptCallbackFunction("extract_keychain_keys._on_secitem_return")
            _pending_returns[lr] = []

        _pending_returns[lr].append({
            "result_out_ptr": result_out_ptr,
            "index": idx,
        })
    except Exception as e:
        _log(f"  ⚠️  entry handler exception: {e}")

    return False


def _on_secitem_return(frame, bp_loc, extra_args, internal_dict):
    if _done:
        return False

    try:
        result = _handle_secitem_return(frame)
        # Exit once we've captured both FMF + FMIP (2 items)
        if _secitem_captured >= 2:
            process = frame.GetThread().GetProcess()
            _finish(process)
        return result
    except Exception as e:
        _log(f"  ⚠️  return handler exception: {e}")
        return False


def _handle_secitem_return(frame):
    global _secitem_captured, _secitem_resolved

    pc = frame.GetPC()
    queue = _pending_returns.get(pc) or _pending_returns.get(pc & 0x000000FFFFFFFFFF)
    if not queue:
        return False

    ctx = queue.pop(0)  # FIFO — oldest call returns first
    # Clean up empty queues so the BP can be removed
    addr = pc if pc in _pending_returns else (pc & 0x000000FFFFFFFFFF)
    if addr in _pending_returns and not _pending_returns[addr]:
        del _pending_returns[addr]

    _secitem_resolved += 1
    process = frame.GetThread().GetProcess()
    idx = ctx["index"]
    result_out_ptr = ctx["result_out_ptr"]

    # x0 = OSStatus (0 = success)
    status = frame.FindRegister("x0").GetValueAsSigned()
    if status != 0:
        return False

    # Read result pointer from the output parameter (caller's stack location)
    ptr_bytes = _read_mem(process, result_out_ptr, 8)
    if not ptr_bytes:
        return _try_secitem_objc_dump(frame, process, idx)

    data_ptr = struct.unpack('<Q', ptr_bytes)[0]
    # Strip PAC bits from the data pointer too
    data_ptr = data_ptr & 0x000000FFFFFFFFFF
    if not data_ptr:
        return False

    return _save_secitem_result(frame, process, idx, data_ptr)


def _try_secitem_objc_dump(frame, process, idx):
    """Fallback: try to find the result via ObjC expression eval."""
    # Try x19-x21 — callee-saved registers that might hold the result pointer
    for reg_name in ["x19", "x20", "x21"]:
        reg = frame.FindRegister(reg_name)
        if not reg.IsValid():
            continue
        candidate = reg.GetValueAsUnsigned() & 0x000000FFFFFFFFFF
        if candidate < 0x100000000:  # skip small values (not heap pointers)
            continue
        # Probe if it looks like a CFData/NSData
        opts = lldb.SBExpressionOptions()
        opts.SetTimeoutInMicroSeconds(2_000_000)
        opts.SetTryAllThreads(False)
        r = frame.EvaluateExpression(
            f'(long)CFDataGetLength((void *){candidate})', opts)
        if not r.GetError().Fail():
            length = r.GetValueAsUnsigned()
            if 0 < length < 1_000_000:
                return _save_cfdata(frame, process, idx, candidate)
    return False


def _save_secitem_result(frame, process, idx, result_ptr):
    """Identify the SecItemCopyMatching result type and save it."""
    global _secitem_captured

    opts = lldb.SBExpressionOptions()
    opts.SetTimeoutInMicroSeconds(5_000_000)
    opts.SetTryAllThreads(False)

    # Identify the object type via ObjC runtime
    opts.SetLanguage(lldb.eLanguageTypeObjC)
    r_cls = frame.EvaluateExpression(
        f'(const char *)object_getClassName((id){result_ptr})', opts)
    cls_name = None
    if not r_cls.GetError().Fail():
        cls_ptr = r_cls.GetValueAsUnsigned()
        if cls_ptr:
            cls_name = _read_cstring(process, cls_ptr, 128)
    if not cls_name:
        # Can't identify type — try serializing the whole thing as plist
        return _serialize_and_save(frame, process, idx, result_ptr, opts)

    if "Data" in cls_name:
        # NSData / NSConcreteMutableData / etc
        return _save_cfdata(frame, process, idx, result_ptr, opts)
    elif "Dictionary" in cls_name:
        # NSDictionary — try to extract v_Data (raw keychain value)
        return _save_dict_result(frame, process, idx, result_ptr, opts)
    elif "Array" in cls_name:
        # NSArray — serialize the whole thing
        return _serialize_and_save(frame, process, idx, result_ptr, opts)
    else:
        return _serialize_and_save(frame, process, idx, result_ptr, opts)


def _read_nsstring(frame, process, ptr, opts):
    """Read an NSString value from an ObjC pointer."""
    ptr = ptr & 0x000000FFFFFFFFFF
    if not ptr:
        return None
    r_str = frame.EvaluateExpression(
        f'(const char *)[(NSString *){ptr} UTF8String]', opts)
    if not r_str.GetError().Fail():
        str_ptr = r_str.GetValueAsUnsigned()
        if str_ptr:
            return _read_cstring(process, str_ptr, 256)
    return None


def _save_dict_result(frame, process, idx, dict_ptr, opts):
    """Extract v_Data from a keychain result dictionary, or serialize the whole dict."""
    global _secitem_captured

    # Try to identify the keychain item by its service name (svce attribute)
    opts.SetLanguage(lldb.eLanguageTypeObjC)
    service_name = None
    for attr, label in [("svce", "service"), ("acct", "account"), ("labl", "label")]:
        r_attr = frame.EvaluateExpression(
            f'(id)[(NSDictionary *){dict_ptr} objectForKey:@"{attr}"]', opts)
        if not r_attr.GetError().Fail():
            attr_ptr = r_attr.GetValueAsUnsigned() & 0x000000FFFFFFFFFF
            if attr_ptr:
                attr_val = _read_nsstring(frame, process, attr_ptr, opts)
                if attr_val:
                    if attr == "svce" and not service_name:
                        service_name = attr_val

    # Try to get the "v_Data" key (kSecValueData) — the raw secret
    r_data = frame.EvaluateExpression(
        f'(id)[(NSDictionary *){dict_ptr} objectForKey:@"v_Data"]', opts)
    if not r_data.GetError().Fail():
        v_data_ptr = r_data.GetValueAsUnsigned() & 0x000000FFFFFFFFFF
        if v_data_ptr:
            # Use service name for filename if available
            name = service_name if service_name else f"secitem_{idx}"
            return _save_cfdata(frame, process, idx, v_data_ptr, opts, name)

    # No v_Data — serialize the whole dictionary as binary plist
    return _serialize_and_save(frame, process, idx, dict_ptr, opts)


def _serialize_and_save(frame, process, idx, obj_ptr, opts):
    """Serialize an ObjC object to NSData via NSPropertyListSerialization and save."""
    global _secitem_captured

    opts.SetLanguage(lldb.eLanguageTypeObjC)
    r_ser = frame.EvaluateExpression(
        f'(id)[NSPropertyListSerialization dataWithPropertyList:(id){obj_ptr}'
        f' format:200 options:0 error:nil]', opts)
    if r_ser.GetError().Fail():
        # Last resort: get the ObjC description string
        r_desc = frame.EvaluateExpression(
            f'(id)[(id){obj_ptr} description]', opts)
        if not r_desc.GetError().Fail():
            desc_ptr = r_desc.GetValueAsUnsigned() & 0x000000FFFFFFFFFF
            if desc_ptr:
                desc = _read_cstring(process, desc_ptr, 4096)
                if desc:
                    filename = f"secitem_{idx}.txt"
                    with open(OUT_DIR / filename, "w") as f:
                        f.write(desc)
                    _secitem_captured += 1
                    _log(f"  ✅  {filename}")
                    return False
        return False

    ser_ptr = r_ser.GetValueAsUnsigned() & 0x000000FFFFFFFFFF
    if not ser_ptr:
        return False

    return _save_cfdata(frame, process, idx, ser_ptr, opts)


def _save_cfdata(frame, process, idx, data_ptr, opts=None, name=None):
    """Read a CFData/NSData and save to disk."""
    global _secitem_captured

    if opts is None:
        opts = lldb.SBExpressionOptions()
        opts.SetTimeoutInMicroSeconds(5_000_000)
        opts.SetTryAllThreads(False)

    r_len = frame.EvaluateExpression(
        f'(long)CFDataGetLength((void *){data_ptr})', opts)
    if r_len.GetError().Fail():
        opts.SetLanguage(lldb.eLanguageTypeObjC)
        r_len = frame.EvaluateExpression(
            f'(unsigned long)[(NSData *){data_ptr} length]', opts)
        if r_len.GetError().Fail():
            return False

    length = r_len.GetValueAsUnsigned()
    if length == 0 or length > 1_000_000:
        return False

    r_bytes = frame.EvaluateExpression(
        f'(void *)CFDataGetBytePtr((void *){data_ptr})', opts)
    if r_bytes.GetError().Fail():
        opts.SetLanguage(lldb.eLanguageTypeObjC)
        r_bytes = frame.EvaluateExpression(
            f'(void *)[(NSData *){data_ptr} bytes]', opts)
        if r_bytes.GetError().Fail():
            return False

    bytes_ptr = r_bytes.GetValueAsUnsigned()
    data = _read_mem(process, bytes_ptr, length)
    if not data:
        return False

    filename = f"{name}.bplist" if name else f"secitem_{idx}.bplist"
    with open(OUT_DIR / filename, "wb") as f:
        f.write(data)
    _secitem_captured += 1
    _log(f"  ✅  {filename} ({length} bytes)")

    return False


# ── Module init ───────────────────────────────────────────────────────────

def __lldb_init_module(debugger, internal_dict):
    global _bp_key_v2, _bp_secitem

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        _log("  ❌  No valid target")
        return

    _bp_key_v2 = target.BreakpointCreateByName("sqlite3_key_v2")
    _bp_key_v2.SetScriptCallbackFunction("extract_keychain_keys._on_sqlite3_key_v2")

    _bp_secitem = target.BreakpointCreateByName("SecItemCopyMatching")
    _bp_secitem.SetScriptCallbackFunction("extract_keychain_keys._on_secitem_entry")

    _log("  ⏳  Waiting for key derivation...")
