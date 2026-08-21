"""
extract_keychain_keys.py — lldb script to extract Find My keychain keys.

Attaches to FindMy.app and captures FMF/FMIP keychain items via a
SecItemCopyMatching entry breakpoint.

Usage:
  sudo lldb --wait-for -n FindMy \
    -o "command script import extract_keychain_keys.py" \
    -o "c" -o "quit"

Keys are written to disk only — never printed to terminal.

── Why the return value is captured via a breakpoint *condition*, not a
   second Python callback ──────────────────────────────────────────────

The entry breakpoint identifies which of the two Find My keychain queries
(FMFDataManager / FMIPDataManager) is in flight from its query dict, but
the actual result is only available once SecItemCopyMatching returns. An
earlier version of this script handled that by creating a second
breakpoint at the call's return address and wiring a Python callback to it
with SBBreakpoint.SetScriptCallbackFunction().

On newer lldb (seen on lldb-1700, Xcode 16 / macOS 15.7) that call is
broken when done from inside another already-running Python breakpoint
callback:
  - called on the same thread (nested), it raises
    "KeyError: 'lldb_autogen_python_bp_callback_func__N'" immediately —
    the exec() lldb uses to register the generated wrapper function isn't
    reentrant;
  - deferred to a separate thread instead, it just deadlocks forever —
    lldb appears to serialize that specific operation against whichever
    thread is currently inside a running script callback, and here that
    thread never becomes free (our breakpoints are designed to always
    auto-continue, so the driving "process continue" command never
    "finishes" the way batch mode expects).
  - the same operation also breaks in `breakpoint set` + `breakpoint
    command add -F ...` form driven through the command interpreter
    (HandleCommand) — it's the same underlying non-reentrant mechanism.

Plain breakpoint creation/mutation (BreakpointCreateByAddress,
SetCondition) is *not* affected — it works fine nested. So instead of
wiring a second Python callback, we arm the return-address breakpoint with
a C/ObjC *condition* expression, evaluated entirely by lldb's own
Clang-based expression evaluator with no Python involved: it reads the
result out of the caller's stack slot, identifies the NSData/NSDictionary
result, and writes the raw bytes straight to disk via open()/write().
It's written to always evaluate to 0 (false), so lldb never treats the
breakpoint as "hit" publicly either — which matters here, since in this
--wait-for + batch-mode `-o` setup, lldb quits the whole session the
moment it sees an unhandled stop with no more queued `-o` commands.
"""

import lldb
import struct

_bp_secitem = None
_secitem_count = 0
# Return-address -> breakpoint. FMF and FMIP return through the *same* call
# site, so arming a fresh breakpoint per call leaves the earlier one live with
# a condition that still points at the previous call's result slot. That slot is
# stack memory which has since been reused, so the condition dereferences
# garbage, the expression errors, and an erroring condition counts as a *stop* —
# which ends the batch-mode session and loses the capture. Keep one breakpoint
# per address and swap its condition instead.
_ret_bps = {}


def _log(msg):
    print(msg, flush=True)


def _is_x86(frame):
    triple = frame.GetThread().GetProcess().GetTarget().GetTriple() or ""
    return triple.startswith("x86_64")


def _arg(frame, n):
    """n-th integer/pointer arg under the platform C ABI (System V AMD64 / AAPCS64)."""
    names = (["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if _is_x86(frame)
             else ["x0", "x1", "x2", "x3", "x4", "x5"])
    return frame.FindRegister(names[n]).GetValueAsUnsigned()


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


# ARM64e adds Pointer Authentication Codes in the high bits of pointers; mask
# to the low 40 bits to recover the real address. On x86_64 there is no PAC,
# AND user-space pointers can use up to 47 bits (the 0x7fff_xxxx_xxxx range
# for Catalyst apps), so masking would corrupt them.

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
    r_str = frame.EvaluateExpression(
        f'(const char *)[(NSString *){attr_ptr} UTF8String]', opts)
    if r_str.GetError().Fail():
        return None
    str_ptr = r_str.GetValueAsUnsigned()
    if not str_ptr:
        return None
    return _read_cstring(process, str_ptr, 256)


def _capture_condition(result_out_ptr, filename, retval_reg):
    """A breakpoint condition (C/ObjC, evaluated natively by lldb) that
    reads the SecItemCopyMatching result at `result_out_ptr` and, if it
    looks like a plausible NSData or an NSDictionary wrapping one (the
    v_Data / kSecValueData attribute), writes the raw bytes to a file
    named `filename` inside NSTemporaryDirectory().

    FindMy.app is App-Sandboxed (com.apple.security.app-sandbox), so a
    plain open() to an arbitrary path outside its container silently fails
    (fd == -1) even though SIP/AMFI being relaxed lets us attach/breakpoint
    it just fine — the sandbox is a separate, per-process kernel policy
    that injected code still runs under. NSTemporaryDirectory() resolves
    to that container's own writable tmp dir
    (~/Library/Containers/<bundle-id>/Data/tmp/), which the sandbox does
    allow. extract.sh copies the file out from there afterward, run as the
    normal (unsandboxed) user.

    Always evaluates to 0 so the breakpoint never actually "stops".
    """
    escaped_name = filename.replace("\\", "\\\\").replace('"', '\\"')
    body = (
        # The return-value register holds the OSStatus at this point — the
        # caller's frame right after the call returns. On failure the
        # callee often leaves *result_out_ptr untouched (stale/
        # uninitialized), so it must not be dereferenced unless the call
        # actually succeeded.
        # Build the destination path first and bail out if it already exists.
        #
        # This breakpoint sits on a *return address*, so it fires for every call
        # returning through that site — including the keychain reads we skip at
        # entry because they are neither FMF nor FMIP. Those carry a different
        # result slot, so dereferencing ours reads whatever now occupies that
        # stack memory; the plausibility check below is not enough to stop
        # object_getClassName() faulting on it (EXC_BAD_ACCESS). An erroring
        # condition counts as a stop, which ends the batch session and loses the
        # remaining key.
        #
        # Once we have captured, there is nothing left to do, so short-circuit
        # before touching any pointer. That makes re-entry harmless.
        "char path[1024]; "
        "NSString *tmpDirStr0 = (NSString *)(id)NSTemporaryDirectory(); "
        "const char *tmpDir0 = (const char *)[tmpDirStr0 UTF8String]; "
        "(unsigned long)strlcpy(path, tmpDir0, sizeof(path)); "
        f'(unsigned long)strlcat(path, "{escaped_name}", sizeof(path)); '
        "int done = ((int)access(path, 0) == 0); "
        f"int status = (int)${retval_reg}; "
        f"void *rp = (!done && status == 0) ? (void *)0x{result_out_ptr:x} : (void *)0; "
        "void *dp = rp ? *(void **)rp : (void *)0; "
        "id obj = (id)dp; "
        "id dataObj = ((unsigned long)obj > 0x100000000) ? obj : (id)0; "
        "const char *cls = dataObj ? (const char *)object_getClassName(dataObj) : (const char *)0; "
        'if (dataObj && cls && (char *)strstr(cls, "Dictionary") '
        "    && (BOOL)[dataObj respondsToSelector:@selector(objectForKey:)]) { "
        '  id inner = (id)[(NSDictionary *)dataObj objectForKey:@"v_Data"]; '
        "  dataObj = ((unsigned long)inner > 0x100000000) ? inner : (id)0; "
        "} "
        "BOOL rLen = dataObj ? (BOOL)[dataObj respondsToSelector:@selector(length)] : NO; "
        "BOOL rBytes = dataObj ? (BOOL)[dataObj respondsToSelector:@selector(bytes)] : NO; "
        "if (dataObj && rLen && rBytes) { "
        "  unsigned long len = (unsigned long)[(NSData *)dataObj length]; "
        "  void *bytes = (void *)[(NSData *)dataObj bytes]; "
        "  if (len > 0 && len < 1000000 && bytes) { "
        "    int fd = (int)open(path, 1537, 384); "
        "    if (fd >= 0) { (long)write(fd, bytes, len); (int)close(fd); } "
        "  } "
        "} "
    )
    return "({ " + body + "0; })"


def _on_secitem_entry(frame, bp_loc, extra_args, internal_dict):
    global _secitem_count, _ret_bps

    try:
        query_ptr = _arg(frame, 0)
        result_out_ptr = _arg(frame, 1)
        service = _query_service_name(frame, query_ptr)

        # Only track the two Find My keychain services
        if service not in ("FMIPDataManager", "FMFDataManager"):
            return False

        lr_raw = _entry_return_address(frame)
        lr = _strip_pac(frame, lr_raw)
        _log(f"  🔔  SecItemCopyMatching [{service}]: result_out=0x{result_out_ptr:x} retaddr=0x{lr:x}")

        if not result_out_ptr or not lr:
            return False

        _secitem_count += 1
        target = frame.GetThread().GetProcess().GetTarget()
        filename = f"{service}.bplist"

        # FMF and FMIP share this return address, so reuse the breakpoint and
        # replace its condition rather than stacking a second one (see _ret_bps).
        retval_reg = "rax" if _is_x86(frame) else "x0"
        bp_ret = _ret_bps.get(lr)
        if bp_ret is None or not bp_ret.IsValid():
            bp_ret = target.BreakpointCreateByAddress(lr)
            _ret_bps[lr] = bp_ret
        bp_ret.SetCondition(_capture_condition(result_out_ptr, filename, retval_reg))
        _log(f"  🛠️  armed capture for [{service}] at 0x{lr:x} → (sandbox tmp)/{filename}")
    except Exception as e:
        _log(f"  ⚠️  entry handler exception: {e}")

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
