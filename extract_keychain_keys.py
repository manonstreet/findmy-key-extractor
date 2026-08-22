"""
extract_keychain_keys.py — lldb script to extract Find My keychain keys.

Attaches to FindMy.app and captures FMF/FMIP keychain items via
SecItemCopyMatching breakpoints.

Usage:
  sudo lldb --wait-for -n FindMy \
    -o "command script import extract_keychain_keys.py" \
    -o "c" -o "quit"

Keys are written to disk only — never printed to terminal.
"""

import contextlib
import lldb
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "keys"

_bp_secitem = None
_secitem_count = 0
_secitem_captured = 0
_secitem_resolved = 0
_pending_returns = {}
# Return addresses that already carry a breakpoint, mapped to its breakpoint ID.
# Outlives the pending queue, which is deleted when it empties — that deletion is
# what allowed duplicates. The ID is kept so the breakpoint can be deleted and
# recreated around a capture (see _ret_bp_removed).
_ret_bp_ids = {}
_done = False


def _log(msg):
    print(msg, flush=True)


def _create_ret_bp(target, addr):
    """Create the return breakpoint at addr, with its command wiring.

    Factored out of the entry handler so that _ret_bp_removed can put an
    identical breakpoint back after deleting one.
    """
    bp_ret = target.BreakpointCreateByAddress(addr)

    # Work around an LLDB issue triggered when a Python breakpoint
    # callback installs another Python breakpoint callback.
    #
    # Instead, attach ordinary LLDB commands to the dynamically
    # created return breakpoint and invoke the Python handler from
    # LLDB's command interpreter.
    commands = lldb.SBStringList()
    commands.AppendString(
        "script import lldb, extract_keychain_keys; "
        "extract_keychain_keys._on_secitem_return_command(lldb.frame)"
    )
    bp_ret.SetCommandLineCommands(commands)
    bp_ret.SetAutoContinue(True)
    return bp_ret


@contextlib.contextmanager
def _ret_bp_removed(target, *addrs):
    """Delete the return breakpoint for the duration of a capture, then restore.

    Iteration 1 established that *disabling* a breakpoint does not remove its
    trap during expression evaluation — with every breakpoint disabled the
    expression was still interrupted, and the reason string merely lost its
    location number ("breakpoint 2.." against the baseline's "breakpoint 2.1.").
    Disabling it made the drop rate twice as bad. Deleting is the one operation
    that must actually remove the trap.

    Takes several candidate addresses because the pending queue is keyed on
    either the raw or the PAC-stripped PC and the breakpoint may sit under
    either.
    """
    removed = []
    for addr in addrs:
        bp_id = _ret_bp_ids.get(addr)
        if bp_id is None:
            continue
        if target.BreakpointDelete(bp_id):
            removed.append(addr)
            del _ret_bp_ids[addr]
        else:
            _log(f"  ⚠️  could not delete return breakpoint {bp_id} at 0x{addr:x}")
    try:
        yield
    finally:
        for addr in removed:
            try:
                _ret_bp_ids[addr] = _create_ret_bp(target, addr).GetID()
            except Exception as e:
                _log(f"  ⚠️  could not restore return breakpoint at 0x{addr:x}: {e}")


def _is_x86(frame):
    triple = frame.GetThread().GetProcess().GetTarget().GetTriple() or ""
    return triple.startswith("x86_64")


def _arg(frame, n):
    """n-th integer/pointer arg under the platform C ABI (System V AMD64 / AAPCS64)."""
    names = (["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if _is_x86(frame)
             else ["x0", "x1", "x2", "x3", "x4", "x5"])
    return frame.FindRegister(names[n]).GetValueAsUnsigned()


def _retval_signed(frame):
    """Integer return value, signed (for OSStatus etc)."""
    name = "rax" if _is_x86(frame) else "x0"
    return frame.FindRegister(name).GetValueAsSigned()


def _entry_return_address(frame):
    """At a function-entry breakpoint, the address the function will return to.

    On ARM64 this is the link register `lr`. On x86_64 the `call` instruction
    just pushed the return address, so it's at `*(uint64_t*)$rsp`.
    """
    if _is_x86(frame):
        process = frame.GetThread().GetProcess()
        rsp = frame.FindRegister("rsp").GetValueAsUnsigned()
        if not rsp:
            return 0
        err = lldb.SBError()
        data = process.ReadMemory(int(rsp), 8, err)
        if err.Fail() or not data:
            return 0
        return struct.unpack("<Q", bytes(data))[0]
    return frame.FindRegister("lr").GetValueAsUnsigned()


def _callee_saved_candidates(frame):
    """Callee-saved registers that may still hold a value the function set up."""
    if _is_x86(frame):
        # rbp is also callee-saved but is typically the frame pointer; skip it.
        return ["rbx", "r12", "r13", "r14", "r15"]
    return ["x19", "x20", "x21"]


# ARM64e adds Pointer Authentication Codes in the high bits of pointers; mask
# to the low 40 bits to recover the real address. On x86_64 there is no PAC,
# AND user-space pointers can use up to 47 bits (the 0x7fff_xxxx_xxxx range
# for Catalyst apps), so masking would corrupt them. Use _strip_pac everywhere
# we previously hardcoded `& 0x000000FFFFFFFFFF`.

_PAC_MASK = 0x000000FFFFFFFFFF


def _strip_pac(frame, ptr):
    return ptr if _is_x86(frame) else (ptr & _PAC_MASK)


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


# ── SecItemCopyMatching — capture all successful results ──────────────────

def _query_service_name(frame, query_ptr):
    """Read svce from the SecItemCopyMatching query dict (arg0)."""
    if not query_ptr:
        return None
    opts = lldb.SBExpressionOptions()
    opts.SetTimeoutInMicroSeconds(2_000_000)
    opts.SetTryAllThreads(False)
    opts.SetLanguage(lldb.eLanguageTypeObjC)
    process = frame.GetThread().GetProcess()
    query_ptr = _strip_pac(frame, query_ptr)
    r = frame.EvaluateExpression(
        f'(id)[(NSDictionary *){query_ptr} objectForKey:@"svce"]', opts)
    if r.GetError().Fail():
        return None
    attr_ptr = _strip_pac(frame, r.GetValueAsUnsigned())
    if not attr_ptr:
        return None
    return _read_nsstring(frame, process, attr_ptr, opts)


def _on_secitem_entry(frame, bp_loc, extra_args, internal_dict):
    global _secitem_count
    if _done:
        return False

    try:
        query_ptr = _arg(frame, 0)
        result_out_ptr = _arg(frame, 1)
        service = _query_service_name(frame, query_ptr)

        # Only track the two Find My keychain services
        if service not in ("FMIPDataManager", "FMFDataManager"):
            return False

        lr_raw = _entry_return_address(frame)
        _log(f"  🔔  SecItemCopyMatching [{service}]: result_out=0x{result_out_ptr:x} retaddr=0x{lr_raw:x}")
        lr = _strip_pac(frame, lr_raw)

        if not result_out_ptr or not lr:
            return False

        _secitem_count += 1
        idx = _secitem_count

        target = frame.GetThread().GetProcess().GetTarget()
        # One breakpoint per return address, tracked separately from the pending
        # queue. Keying off _pending_returns alone is not the same thing: the
        # queue is deleted once it empties, so the next call to the same address
        # takes this branch again and creates a *second* breakpoint there. They
        # accumulate, and a caught failure showed two of them interrupting one
        # expression — "Execution was interrupted, reason: breakpoint 2.1 3.1".
        if lr not in _ret_bp_ids:
            _ret_bp_ids[lr] = _create_ret_bp(target, lr).GetID()

        if lr not in _pending_returns:
            _pending_returns[lr] = []

        _pending_returns[lr].append({
            "result_out_ptr": result_out_ptr,
            "index": idx,
            "service": service,
        })
    except Exception as e:
        _log(f"  ⚠️  entry handler exception: {e}")

    return False


def _on_secitem_return_command(frame):
    """Return-breakpoint handler invoked as a regular LLDB command.

    This avoids LLDB's nested Python breakpoint callback issue.
    """
    global _secitem_captured

    if _done or not frame or not frame.IsValid():
        return

    try:
        _handle_secitem_return(frame)

        if _secitem_captured >= 2:
            process = frame.GetThread().GetProcess()
            _finish(process)

    except Exception as e:
        _log(f"  ⚠️  return command exception: {e}")


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
    pc_stripped = _strip_pac(frame, pc)
    queue = _pending_returns.get(pc) or _pending_returns.get(pc_stripped)
    if not queue:
        return False

    ctx = queue.pop(0)  # FIFO — oldest call returns first
    # Clean up empty queues so the BP can be removed
    addr = pc if pc in _pending_returns else pc_stripped
    if addr in _pending_returns and not _pending_returns[addr]:
        del _pending_returns[addr]

    _secitem_resolved += 1
    process = frame.GetThread().GetProcess()
    idx = ctx["index"]
    result_out_ptr = ctx["result_out_ptr"]

    # Return register (x0/rax) holds OSStatus; 0 = success
    status = _retval_signed(frame)
    if status != 0:
        _log(f"  ⚠️  [{ctx.get('service')}] dropped — OSStatus {status}")
        return False

    # Read result pointer from the output parameter (caller's stack location)
    ptr_bytes = _read_mem(process, result_out_ptr, 8)
    if not ptr_bytes:
        return _try_secitem_objc_dump(frame, process, idx)

    data_ptr = struct.unpack('<Q', ptr_bytes)[0]
    data_ptr = _strip_pac(frame, data_ptr)
    if not data_ptr:
        _log(f"  ⚠️  [{ctx.get('service')}] dropped — result slot held null")
        return False

    # Catch-all. _save_secitem_result has around a dozen internal exits and
    # returns False whether or not it wrote a file, so its return value cannot
    # report success — measure the counter instead. Without this a capture can
    # fail having said nothing, which is exactly how a 12% second-capture drop
    # stayed invisible on two architectures.
    before = _secitem_captured
    # Every expression the capture runs — the class probe, the v_Data lookup,
    # the CFData reads — executes target code that returns back through this
    # address. All 24 drops measured in iteration 1 died at the v_Data lookup.
    # Remove the trap for the whole capture rather than for one call.
    target = process.GetTarget()
    with _ret_bp_removed(target, pc, pc_stripped):
        result = _save_secitem_result(frame, process, idx, data_ptr)
    if _secitem_captured == before:
        _log(f"  ⚠️  [{ctx.get('service')}] dropped — 0x{data_ptr:x} produced no key")
    return result


def _try_secitem_objc_dump(frame, process, idx):
    """Fallback: try to find the result via ObjC expression eval."""
    # Try callee-saved registers that might still hold the result pointer.
    # ARM64 AAPCS: x19-x21. System V AMD64: rbx, r12-r15.
    for reg_name in _callee_saved_candidates(frame):
        reg = frame.FindRegister(reg_name)
        if not reg.IsValid():
            continue
        candidate = _strip_pac(frame, reg.GetValueAsUnsigned())
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
        _log(f"     ↳ 0x{result_ptr:x}: class unidentified "
             f"({r_cls.GetError().GetCString() or 'no name'}) → serialize")
        return _serialize_and_save(frame, process, idx, result_ptr, opts)

    if "Data" in cls_name:
        # NSData / NSConcreteMutableData / etc
        _log(f"     ↳ 0x{result_ptr:x}: {cls_name} → cfdata")
        return _save_cfdata(frame, process, idx, result_ptr, opts)
    elif "Dictionary" in cls_name:
        # NSDictionary — try to extract v_Data (raw keychain value)
        _log(f"     ↳ 0x{result_ptr:x}: {cls_name} → dict")
        return _save_dict_result(frame, process, idx, result_ptr, opts)
    elif "Array" in cls_name:
        # NSArray — serialize the whole thing
        return _serialize_and_save(frame, process, idx, result_ptr, opts)
    else:
        return _serialize_and_save(frame, process, idx, result_ptr, opts)


def _read_nsstring(frame, process, ptr, opts):
    """Read an NSString value from an ObjC pointer."""
    ptr = _strip_pac(frame, ptr)
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
            attr_ptr = _strip_pac(frame, r_attr.GetValueAsUnsigned())
            if attr_ptr:
                attr_val = _read_nsstring(frame, process, attr_ptr, opts)
                if attr_val:
                    if attr == "svce" and not service_name:
                        service_name = attr_val

    # Try to get the "v_Data" key (kSecValueData) — the raw secret
    r_data = frame.EvaluateExpression(
        f'(id)[(NSDictionary *){dict_ptr} objectForKey:@"v_Data"]', opts)
    if r_data.GetError().Fail():
        _log(f"     ↳ dict 0x{dict_ptr:x}: objectForKey v_Data failed "
             f"({r_data.GetError().GetCString() or 'expression failed'})")
    elif not _strip_pac(frame, r_data.GetValueAsUnsigned()):
        _log(f"     ↳ dict 0x{dict_ptr:x}: no v_Data in this dictionary")
    if not r_data.GetError().Fail():
        v_data_ptr = _strip_pac(frame, r_data.GetValueAsUnsigned())
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
            desc_ptr = _strip_pac(frame, r_desc.GetValueAsUnsigned())
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

    ser_ptr = _strip_pac(frame, r_ser.GetValueAsUnsigned())
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
            _log(f"  ⚠️  cfdata 0x{data_ptr:x}: length unavailable "
                 f"({r_len.GetError().GetCString() or 'expression failed'})")
            return False

    length = r_len.GetValueAsUnsigned()
    if length == 0 or length > 1_000_000:
        _log(f"  ⚠️  cfdata 0x{data_ptr:x}: length {length} out of range")
        return False

    r_bytes = frame.EvaluateExpression(
        f'(void *)CFDataGetBytePtr((void *){data_ptr})', opts)
    if r_bytes.GetError().Fail():
        opts.SetLanguage(lldb.eLanguageTypeObjC)
        r_bytes = frame.EvaluateExpression(
            f'(void *)[(NSData *){data_ptr} bytes]', opts)
        if r_bytes.GetError().Fail():
            _log(f"  ⚠️  cfdata 0x{data_ptr:x}: byte pointer unavailable "
                 f"({r_bytes.GetError().GetCString() or 'expression failed'}), len={length}")
            return False

    bytes_ptr = r_bytes.GetValueAsUnsigned()
    data = _read_mem(process, bytes_ptr, length)
    if not data:
        _log(f"  ⚠️  cfdata 0x{data_ptr:x}: read of {length}B at 0x{bytes_ptr:x} "
             f"returned nothing")
        return False

    filename = f"{name}.bplist" if name else f"secitem_{idx}.bplist"
    with open(OUT_DIR / filename, "wb") as f:
        f.write(data)
    _secitem_captured += 1
    _log(f"  ✅  {filename} ({length} bytes)")

    return False


# ── Module init ───────────────────────────────────────────────────────────

def __lldb_init_module(debugger, internal_dict):
    global _bp_secitem

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        _log("  ❌  No valid target")
        return

    triple = target.GetTriple() or "(unknown)"
    _log(f"  📍  target triple: {triple}")

    _bp_secitem = target.BreakpointCreateByName("SecItemCopyMatching")
    _bp_secitem.SetScriptCallbackFunction("extract_keychain_keys._on_secitem_entry")

    _log(f"  ⏳  Waiting for keychain reads... (SecItemCopyMatching: {_bp_secitem.GetNumLocations()} locs)")
