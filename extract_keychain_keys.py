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

import lldb
import re
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "keys"

_bp_secitem = None
_secitem_count = 0
_secitem_captured = 0
_secitem_resolved = 0
_pending_returns = {}
# Candidate C: watchpoint ID -> the call it is watching. The result slot is a
# stack address in the caller's frame, so it is unique per in-flight call and
# needs no FIFO queue — which also removes the pop(0) mismatch that made the
# original drop invisible.
_pending_watch = {}
_wp_spurious = 0
# Return addresses that already carry a breakpoint. Outlives the pending queue,
# which is deleted when it empties — that deletion is what allowed duplicates.
_ret_bp_addrs = set()
_done = False


def _log(msg):
    print(msg, flush=True)


def _run_cmd(target, command):
    """Run one lldb command, returning its output or None."""
    res = lldb.SBCommandReturnObject()
    target.GetDebugger().GetCommandInterpreter().HandleCommand(command, res)
    if not res.Succeeded():
        _log(f"  ⚠️  lldb command failed: {command} → {res.GetError().strip()}")
        return None
    return res.GetOutput() or ""


def _watch_result_slot(target, addr):
    """Set a write watchpoint on the 8-byte result slot; return its ID.

    Driven through the command interpreter rather than SBTarget.WatchAddress:
    that method's signature changed across the lldb versions this has to run on
    (1700 on the Intel rig, 1703 and 2100 here), and the interpreter spelling is
    stable across all three. The command list ends in `continue` for the same
    reason the return breakpoint used SetAutoContinue — the batch-mode session
    quits the moment it sees a stop with no queued commands left.
    """
    out = _run_cmd(target, f"watchpoint set expression -w write -s 8 -- {addr}")
    if out is None:
        return None
    # The ID comes out of the command's own text — "Watchpoint created:
    # Watchpoint 1: addr = 0x…". SBTarget.GetLastCreatedWatchpoint does not
    # exist on lldb 1700, which is the version on the Intel rig, so the two
    # SB fallbacks below are only reached if the wording ever changes.
    wp_id = None
    m = re.search(r"Watchpoint (\d+):", out)
    if m:
        wp_id = int(m.group(1))
    else:
        try:
            n = target.GetNumWatchpoints()
            if n:
                wp = target.GetWatchpointAtIndex(n - 1)
                if wp and wp.IsValid():
                    wp_id = wp.GetID()
        except Exception as e:
            _log(f"  ⚠️  could not enumerate watchpoints: {e}")
    if wp_id is None:
        _log(f"  ⚠️  watchpoint on 0x{addr:x} set but its ID could not be read; "
             f"output was: {out.strip()[:200]}")
        return None
    # One -o only. Passing two ("script …" then "continue") registers just the
    # last of them — measured: lldb reported `Command #1 'continue'` and the
    # script never ran, so the watchpoint was never deleted and fired 27,567
    # times on a stack slot that every later call reuses. The handler resumes
    # the process itself instead; watchpoints have no SetAutoContinue.
    if _run_cmd(
        target,
        'watchpoint command add '
        '-o "script import lldb, extract_keychain_keys; '
        'extract_keychain_keys._on_result_written(lldb.frame)" '
        f'{wp_id}',
    ) is None:
        return None
    return wp_id


def _on_result_written(frame):
    """Watchpoint handler — SecItemCopyMatching has just written its out-param.

    Invoked as an ordinary lldb command, not a Python breakpoint callback, for
    the same reason the return handler was: nested SetScriptCallbackFunction is
    broken on lldb 1700.

    Every exit resumes the target. Watchpoints have no SetAutoContinue, and the
    batch-mode session quits the instant it sees a stop with no queued commands
    left, so an early return that forgets to continue ends the run.
    """
    if _done or not frame or not frame.IsValid():
        return

    process = None
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()
        target = process.GetTarget()

        if thread.GetStopReason() == lldb.eStopReasonWatchpoint:
            wp_id = thread.GetStopReasonDataAtIndex(0)
            ctx = _pending_watch.pop(wp_id, None)
            if ctx is not None:
                _handle_written_result(frame, process, ctx)
                # Deleting does not take the trap down — measured: `watchpoint
                # delete` reports success and the watchpoint keeps firing from
                # _swift_release_dealloc, nanov2_calloc_type and other code that
                # reuses this stack slot. Same law as breakpoints. So leave it
                # armed with this handler attached and make the spurious hits
                # cheap instead; _wp_spurious counts what that costs.
                _run_cmd(target, f"watchpoint delete {wp_id}")
            else:
                global _wp_spurious
                _wp_spurious += 1
        else:
            _log(f"  ⚠️  watchpoint handler reached on stop reason "
                 f"{thread.GetStopReason()} — not a watchpoint")
    except Exception as e:
        _log(f"  ⚠️  watchpoint handler exception: {e}")

    if _secitem_captured >= 2:
        if process is not None:
            _finish(process)
        return

    if not _done and process is not None:
        try:
            process.Continue()
        except Exception as e:
            _log(f"  ⚠️  could not resume after watchpoint: {e}")


def _handle_written_result(frame, process, ctx):
    """Read the freshly written result pointer and capture it."""
    global _secitem_captured

    ptr_bytes = _read_mem(process, ctx["result_out_ptr"], 8)
    if not ptr_bytes:
        _log(f"  ⚠️  [{ctx.get('service')}] dropped — result slot unreadable")
        return
    data_ptr = _strip_pac(frame, struct.unpack('<Q', ptr_bytes)[0])
    if not data_ptr:
        # The callee may zero the slot before filling it; that write is not the
        # one we want and is reported rather than silently ignored.
        _log(f"  ⚠️  [{ctx.get('service')}] result slot written null — "
             f"not the result write")
        return

    before = _secitem_captured
    _save_secitem_result(frame, process, ctx["index"], data_ptr)
    if _secitem_captured == before:
        _log(f"  ⚠️  [{ctx.get('service')}] dropped — 0x{data_ptr:x} "
             f"produced no key")


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
    if _wp_spurious:
        _log(f"  ℹ️  {_wp_spurious} spurious watchpoint hits absorbed")
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
        # Candidate C: watch the result slot instead of trapping the return
        # address. Iterations 1 and 2 established that no breakpoint state —
        # ignored, disabled, or deleted — stops lldb aborting an expression that
        # runs target code back through a trapped address. The only way out is
        # not to have a trap there, so the return breakpoint is gone entirely.
        # The watchpoint fires where SecItemCopyMatching writes its out-param,
        # which is inside the callee and nowhere near the shared return address.
        wp_id = _watch_result_slot(target, result_out_ptr)
        if wp_id is None:
            _log(f"  ⚠️  [{service}] could not watch result slot "
                 f"0x{result_out_ptr:x} — this call is lost")
            return False

        _pending_watch[wp_id] = {
            "result_out_ptr": result_out_ptr,
            "index": idx,
            "service": service,
        }
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
