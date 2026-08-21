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
import time
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "keys"

_bp_secitem = None
_secitem_count = 0
_secitem_captured = 0
_secitem_resolved = 0
_pending_returns = {}
# Return addresses that already carry a breakpoint. Outlives the pending queue.
_ret_bp_addrs = set()
# Slack for SP matching: 0 on arm64, 8 on x86_64 (the pushed return address).
_SP_TOLERANCE = 16
_done = False


def _log(msg):
    # Wall clock on every line. Elapsed-from-run-start cannot separate capture
    # cost from relaunch cycles: LocalStorage.key is captured by identical code
    # on both variants and still differed by 2.6s between them, purely because
    # one branch relaunched more before reaching it. A read-to-capture delta is
    # the only honest measure, and it needs timestamps on both ends.
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


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
        # queue. Keying off `_pending_returns` alone means that once a queue
        # empties and is retired, the next call to the same address creates a
        # *second* breakpoint there — the duplicate-breakpoint bug e39e206 fixed
        # on the other branch.
        if lr not in _ret_bp_addrs:
            _ret_bp_addrs.add(lr)
            bp_ret = target.BreakpointCreateByAddress(lr)

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

        if lr not in _pending_returns:
            _pending_returns[lr] = []

        # The stack pointer at entry identifies *this* invocation. The return
        # address does not: every SecItemCopyMatching call from that site shares
        # it, including the ones skipped above for being neither FMF nor FMIP.
        # Matching on order alone lets an unrelated call consume our entry.
        try:
            sp = frame.GetSP()
        except Exception:
            sp = 0

        _pending_returns[lr].append({
            "result_out_ptr": result_out_ptr,
            "index": idx,
            "service": service,
            # The query dictionary this call passed in. If the pointer we later
            # read out of the result slot equals this, we are looking at the
            # query rather than the result — which is the difference between a
            # timing problem and a matching problem, and nothing else we have
            # logged can tell those apart.
            "query_ptr": _strip_pac(frame, query_ptr),
            "sp": sp,
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


def _secitem_file_exists(service):
    """Has this service already been captured to disk?

    v1's idempotence trick, ported. It is what makes a duplicate return, a
    retry, or a relaunch harmless — the capture is attempted at most once per
    service, and every later return for it is a no-op instead of a second write
    or a discarded entry.
    """
    if not service:
        return False
    try:
        return (OUT_DIR / f"{service}.bplist").exists()
    except Exception:
        return False


def _handle_secitem_return(frame):
    """Try every pending call at this return address; keep whatever yields a key.

    There is no reliable way to know *which* queued call a given return belongs
    to. The return address is shared by every SecItemCopyMatching call from that
    site. The stack pointer identifies the frame, not the invocation — FMF and
    FMIP are called from the same function, so their result_out slots are two
    slots in one frame and their SPs are identical. Matching by SP therefore
    degenerates to FIFO for exactly the two calls that matter.

    So stop trying to identify the caller and test the evidence instead: attempt
    each pending entry whose key is not yet on disk, and retire only the ones
    that actually produce a key. This is safe only because capture is idempotent
    and non-destructive — a wrong guess costs one failed read of a stack slot,
    logged, with the entry left in place for the return that does belong to it.
    """
    global _secitem_captured, _secitem_resolved

    pc = frame.GetPC()
    pc_stripped = _strip_pac(frame, pc)
    addr = pc if pc in _pending_returns else pc_stripped
    queue = _pending_returns.get(addr)
    if not queue:
        # Benign once both keys are captured and their entries retired.
        _log(f"  ·  return at 0x{pc_stripped:x} with nothing queued")
        return False

    _secitem_resolved += 1
    process = frame.GetThread().GetProcess()
    captured_any = False

    tried = []
    for ctx in list(queue):
        service = ctx.get("service")

        if _secitem_file_exists(service):
            _retire_entry(addr, ctx)
            continue

        try:
            reason = _attempt_capture(frame, process, ctx)
        except Exception as e:
            tried.append(f"{service}: raised {e}")
            continue

        if reason is None:
            _retire_entry(addr, ctx)
            captured_any = True
        else:
            tried.append(f"{service}: {reason}")

    # Quiet when something was captured — the ✅ line already says so. Loud only
    # when a return produced nothing, which is the case that loses keys.
    if not captured_any and tried:
        _log("  ⚠️  return captured nothing — " + "; ".join(tried))

    return captured_any


def _retire_entry(addr, ctx):
    """Drop one entry, and the queue with it once empty."""
    queue = _pending_returns.get(addr)
    if not queue:
        return
    try:
        queue.remove(ctx)
    except ValueError:
        pass
    if addr in _pending_returns and not _pending_returns[addr]:
        del _pending_returns[addr]


def _attempt_capture(frame, process, ctx):
    """One capture attempt for one pending call.

    Returns None on success, or a short reason string. The reason is what makes
    a failed return diagnosable: with several entries tried per return a miss is
    the normal case, so the caller reports only returns where *nothing* was
    captured — and then it has to say why each attempt failed, or the failure is
    exactly as opaque as the silent `return False` this replaced.
    """
    global _secitem_captured

    idx = ctx["index"]
    result_out_ptr = ctx["result_out_ptr"]

    status = _retval_signed(frame)
    if status != 0:
        return f"OSStatus {status}"

    ptr_bytes = _read_mem(process, result_out_ptr, 8)
    if not ptr_bytes:
        before = _secitem_captured
        _try_secitem_objc_dump(frame, process, idx)
        return None if _secitem_captured > before else f"slot 0x{result_out_ptr:x} unreadable"

    data_ptr = struct.unpack('<Q', ptr_bytes)[0]
    data_ptr = _strip_pac(frame, data_ptr)
    if not data_ptr:
        return "slot held null"

    before = _secitem_captured
    _save_secitem_result(frame, process, idx, data_ptr)
    if _secitem_captured > before:
        return None

    # Identify what we were handed. Probing individual keys is far more robust
    # than reading a description string — each is a plain non-null pointer test,
    # where the previous attempt (allKeys -> description -> UTF8String ->
    # read_cstring) had four ways to come back empty, and did.
    if data_ptr == ctx.get("query_ptr"):
        return f"ptr 0x{data_ptr:x} IS THE QUERY dictionary, not the result"

    # Count errored sends separately from nil returns. Collapsing them is how
    # "no recognisable keychain keys" ended up meaning either "a real dictionary
    # with different contents" or "a pointer that cannot be messaged at all" —
    # which point at opposite fixes.
    present, nil_keys, errors = [], 0, 0
    last_err = None
    for k in ("v_Data", "class", "svce", "acct", "agrp", "labl", "r_Data", "m_Limit"):
        try:
            r = frame.EvaluateExpression(
                f'(id)[(NSDictionary *){data_ptr} objectForKey:@"{k}"]', opts_objc(frame))
            if r.GetError().Fail():
                errors += 1
                last_err = r.GetError().GetCString() or "expression failed"
            elif r.GetValueAsUnsigned():
                present.append(k)
            else:
                nil_keys += 1
        except Exception as e:
            errors += 1
            last_err = str(e)

    # A count message send is the cheapest liveness test: a real dictionary
    # answers it, a bad pointer does not.
    count = None
    try:
        rc = frame.EvaluateExpression(
            f'(long)[(NSDictionary *){data_ptr} count]', opts_objc(frame))
        if not rc.GetError().Fail():
            count = rc.GetValueAsSigned()
    except Exception:
        pass

    if errors:
        return (f"ptr 0x{data_ptr:x} NOT MESSAGEABLE — {errors}/8 sends errored "
                f"(count={count}) last: {last_err}")
    return (f"ptr 0x{data_ptr:x} is a live dict, count={count}, "
            f"{nil_keys}/8 known keys nil, present: {', '.join(present) or 'none'}")


def opts_objc(frame):
    o = lldb.SBExpressionOptions()
    o.SetTimeoutInMicroSeconds(2_000_000)
    o.SetTryAllThreads(False)
    o.SetLanguage(lldb.eLanguageTypeObjC)
    return o


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
    """Identify the SecItemCopyMatching result type and save it.

    Reports what it saw whenever it fails to produce a key. The two failures
    that look identical from outside need opposite fixes: a pointer the ObjC
    runtime cannot name is a stale slot read before the callee's store landed,
    which is a timing problem; a pointer that names a real class we then fail to
    extract from is our handling. Without the class name they are the same
    "yielded no key".
    """
    global _secitem_captured
    before = _secitem_captured

    opts = lldb.SBExpressionOptions()
    opts.SetTimeoutInMicroSeconds(5_000_000)
    opts.SetTryAllThreads(False)

    # Identify the object type via ObjC runtime
    opts.SetLanguage(lldb.eLanguageTypeObjC)
    r_cls = frame.EvaluateExpression(
        f'(const char *)object_getClassName((id){result_ptr})', opts)
    cls_name = None
    cls_err = None
    if r_cls.GetError().Fail():
        cls_err = r_cls.GetError().GetCString() or "expression failed"
    else:
        cls_ptr = r_cls.GetValueAsUnsigned()
        if cls_ptr:
            cls_name = _read_cstring(process, cls_ptr, 128)
        else:
            cls_err = "object_getClassName returned NULL"

    if not cls_name:
        route = "serialize (unidentified)"
        _serialize_and_save(frame, process, idx, result_ptr, opts)
    elif "Data" in cls_name:
        route = f"cfdata ({cls_name})"
        _save_cfdata(frame, process, idx, result_ptr, opts)
    elif "Dictionary" in cls_name:
        route = f"dict ({cls_name})"
        _save_dict_result(frame, process, idx, result_ptr, opts)
    else:
        route = f"serialize ({cls_name})"
        _serialize_and_save(frame, process, idx, result_ptr, opts)

    if _secitem_captured > before:
        return False

    detail = route if cls_name else f"{route}, {cls_err}"
    _log(f"     ↳ 0x{result_ptr:x} → {detail}")
    return False


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
        # This is the one exit that explains a barren return logging nothing at
        # all. object_getClassName is a plain C call needing no runtime lock and
        # it succeeded; objectForKey: is a message send and it did not. If that
        # is why, every ObjC send here fails together and the error will say so.
        _log(f"     ↳ dict 0x{dict_ptr:x}: objectForKey v_Data failed "
             f"({r_data.GetError().GetCString() or 'expression failed'})")
    if not r_data.GetError().Fail():
        v_data_ptr = _strip_pac(frame, r_data.GetValueAsUnsigned())
        if v_data_ptr:
            # Use service name for filename if available
            name = service_name if service_name else f"secitem_{idx}"
            return _save_cfdata(frame, process, idx, v_data_ptr, opts, name)

    # Name the dictionary's keys before falling back. A keychain *result* holds
    # v_Data; the *query* passed in to SecItemCopyMatching holds things like
    # class/svce/r_Data and no value at all. Both are live __NSCFDictionary and
    # both name cleanly via the ObjC runtime, so the class name cannot tell them
    # apart — which is why five failures all looked like "a real dictionary we
    # mishandled" when the question is whether it is the result at all.
    r_keys = frame.EvaluateExpression(
        f'(const char *)[[[(NSDictionary *){dict_ptr} allKeys] description] UTF8String]', opts)
    if not r_keys.GetError().Fail():
        keys_ptr = r_keys.GetValueAsUnsigned()
        if keys_ptr:
            keys = _read_cstring(process, keys_ptr, 512)
            if keys:
                _log(f"     ↳ dict keys: {' '.join(keys.split())}")
    else:
        _log(f"     ↳ dict 0x{dict_ptr:x}: allKeys failed "
             f"({r_keys.GetError().GetCString() or 'expression failed'})")

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
        _log(f"     ↳ serialize 0x{obj_ptr:x} failed "
             f"({r_ser.GetError().GetCString() or 'expression failed'})")
        # Last resort: get the ObjC description string
        r_desc = frame.EvaluateExpression(
            f'(id)[(id){obj_ptr} description]', opts)
        if r_desc.GetError().Fail():
            _log(f"     ↳ description 0x{obj_ptr:x} failed too "
                 f"({r_desc.GetError().GetCString() or 'expression failed'})")
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
    """Read a CFData/NSData and save to disk.

    Every exit here used to be a bare `return False`, which is how a v_Data
    pointer that was found and non-null still produced "yielded no key" five
    times with nothing to say for itself. Four distinct failures live in this
    function and they need different fixes: an object that is not really a
    CFData, a zero length, an unreadable byte pointer, and a failed memory read.
    """
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
            _log(f"     ↳ cfdata 0x{data_ptr:x}: length unavailable "
                 f"({r_len.GetError().GetCString() or 'expression failed'})")
            return False

    length = r_len.GetValueAsUnsigned()
    if length == 0 or length > 1_000_000:
        _log(f"     ↳ cfdata 0x{data_ptr:x}: length {length} out of range")
        return False

    r_bytes = frame.EvaluateExpression(
        f'(void *)CFDataGetBytePtr((void *){data_ptr})', opts)
    if r_bytes.GetError().Fail():
        opts.SetLanguage(lldb.eLanguageTypeObjC)
        r_bytes = frame.EvaluateExpression(
            f'(void *)[(NSData *){data_ptr} bytes]', opts)
        if r_bytes.GetError().Fail():
            _log(f"     ↳ cfdata 0x{data_ptr:x}: byte pointer unavailable "
                 f"({r_bytes.GetError().GetCString() or 'expression failed'}), len={length}")
            return False

    bytes_ptr = r_bytes.GetValueAsUnsigned()
    data = _read_mem(process, bytes_ptr, length)
    if not data:
        _log(f"     ↳ cfdata 0x{data_ptr:x}: read of {length}B at "
             f"0x{bytes_ptr:x} returned nothing")
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
