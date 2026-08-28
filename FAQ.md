# FAQ

Questions that have come up more than once. If you're stuck, run `./diagnose.sh`
first — it reports your environment and lists what's blocking you, and the output
is safe to paste into an issue.

---

## Setup: SIP and AMFI

### Do I really need to disable SIP?

Yes. The keys live in memory in Apple's own processes, and the only way to read
them is to attach a debugger — which SIP exists to prevent. Specifically you need
`ALLOW_TASK_FOR_PID`; without it `lldb` cannot attach and nothing else matters. (A full `csrutil disable` is the only configuration this tool is verified against.)

### `csrutil disable` says it worked, but `csrutil status` still shows restrictions

You're probably on **OpenCore** — an OpenCore Legacy Patcher Mac, or a VM booted
via OpenCore. OpenCore writes `csr-active-config` from its own `config.plist` on
every boot, so a change made in Recovery is silently reverted.

Set it in OpenCore instead:

- **OCLP:** open OpenCore-Patcher → Settings → **Security**, tick the SIP boxes,
  then **Build and Install OpenCore** and reboot. This works — it is how the
  machine this was tested on is configured.
- **Hand-edited OpenCore** (Proxmox and similar): set `csr-active-config` under
  `NVRAM → Add → 7C436110-AB2A-4BBB-A880-FE41995C9F82` in `EFI/OC/config.plist`.
  The mechanics — mounting the EFI, editing with PlistBuddy, validating before
  you reboot on it — are the same as for AMFI, written out in full under
  *"OCLP's 'Disable AMFI' is ticked but AMFI still isn't disabled"* below. The
  only difference is the variable name.

**Note the asymmetry:** OCLP's GUI handles SIP reliably. It is *AMFI* where the
checkbox often produces no boot argument, which is a separate problem with its
own entry below. Getting `csrutil status` right does not mean AMFI is off —
check both.

### In OCLP, which SIP boxes do I tick?

**Tick all of them** (`0xFFF`). Do *not* build with the SIP value showing `0x0` —
that is SIP fully *enabled*, not "unchanged", and on an OCLP Mac it can break root
patching, because those patches need `ALLOW_UNAUTHENTICATED_ROOT`.

**The tested minimum is `0x806`.** Measured on an OCLP machine by setting
`csr-active-config` and running a full extraction at each value:

| value | bits | all three keys? |
|---|---|---|
| `0x0fff` | everything | yes |
| `0x806` | `UNRESTRICTED_FS` + `TASK_FOR_PID` + `UNAUTHENTICATED_ROOT` | **yes** |
| `0x804` | `TASK_FOR_PID` + `UNAUTHENTICATED_ROOT` | no — Find My is killed at launch |

**`ALLOW_UNRESTRICTED_FS` is required**, which is easy to miss: `ALLOW_TASK_FOR_PID`
is necessary but *not* sufficient. The tool reads Find My's cache files and its
container, not just the process.

`ALLOW_UNTRUSTED_KEXTS` is not needed — no kext is involved.
`ALLOW_UNAUTHENTICATED_ROOT` is in the working value only because OCLP root
patching needs it; it is probably not needed by this tool, but that was not
tested. `ALLOW_UNRESTRICTED_NVRAM` is needed before `sudo nvram` will set boot
arguments, which is a separate step.

Ticking everything is still the simplest thing to do.

### On Apple Silicon, "Customized (sip0): 7f" is a FULL disable

This one causes real confusion. Run `csrutil status` and it says *disabled*; run
`sudo bputil -d` on the same machine and it says *Customized (sip0): 7f*. Same
state, different wording. **`0x7f` is what a complete `csrutil disable` produces
on Apple Silicon** — the platform has no `0xfff`, and "Customized" does not mean
"incomplete". A machine reading `7f` has SIP fully disabled.

There is also no `csr-active-config` in NVRAM there — SIP lives in the boot
policy, and only Recovery (hold the power button at startup) can change it.

**What actually matters on Apple Silicon is these two lines from `bputil -d`:**

```text
Security Mode:               Permissive (smb0 && smb1): 1
Boot Args Filtering Status:  Disabled   (sip3): 1
```

Boot arguments are only honoured under **Permissive Security with boot-args
filtering disabled**. Under Reduced Security, `amfi_get_out_of_my_way=1` sits in
`kern.bootargs` looking perfectly correct while AMFI keeps enforcing — so the
usual check passes and extraction still fails, with lldb attaching and then every
memory read failing (`error: memory read failed for 0x0`). `./diagnose.sh`
reports all three lines.

### OCLP's "Disable AMFI" is ticked but AMFI still isn't disabled

On some versions that checkbox doesn't produce a boot argument, and setting one
by hand doesn't stick either — OpenCore rewrites NVRAM on every boot. Work
through it in this order.

**1. Find out what is actually in effect.**

```bash
sysctl kern.bootargs      # what the kernel booted with — authoritative
nvram boot-args           # what is stored — may differ
```

If `amfi_get_out_of_my_way` is missing from the first one, the checkbox didn't
take. On a working OCLP machine it sits alongside OCLP's own arguments:

```
keepsyms=1 debug=0x100 -lilubetaall ipc_control_port_options=0 -nokcmismatchpanic amfi_get_out_of_my_way=1
```

Whatever you do next, keep the existing arguments. Replacing them can leave the
machine unbootable without a config reset.

**2. Try setting it directly.**

```bash
sudo nvram boot-args="<existing args> amfi_get_out_of_my_way=1"
```

If this fails with `(iokit/common) not permitted`, NVRAM protection is still on —
add `ALLOW_UNRESTRICTED_NVRAM` to your SIP configuration and reboot first.

**3. If it reverts after a reboot, OpenCore is overwriting it.**

This is the step most people get stuck on. Values under `NVRAM → Add` are
**only written if the variable does not already exist**, so adding `boot-args`
there does nothing when OpenCore already sets it. To change an existing value it
must *also* be listed under `NVRAM → Delete`.

Set it in the OpenCore configuration rather than with `nvram`. Either use the
OCLP **Advanced** tab, or edit `config.plist` directly — the sequence below is
what worked on a bare-metal OCLP machine.

Mount the EFI partition and check what OpenCore is currently setting:

```bash
sudo diskutil mount disk0s1

/usr/libexec/PlistBuddy -c \
  "Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args" \
  /Volumes/EFI/EFI/OC/config.plist
```

Back it up, then set the value — **including everything already there**, with
`amfi_get_out_of_my_way=1` appended:

```bash
sudo cp /Volumes/EFI/EFI/OC/config.plist /Volumes/EFI/EFI/OC/config.plist.bak

sudo /usr/libexec/PlistBuddy -c \
  "Set :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args \
   keepsyms=1 debug=0x100 -lilubetaall ipc_control_port_options=0 \
   -nokcmismatchpanic amfi_get_out_of_my_way=1" \
  /Volumes/EFI/EFI/OC/config.plist
```

Verify the file is still valid before you reboot on it — a malformed
`config.plist` will not boot:

```bash
plutil -lint /Volumes/EFI/EFI/OC/config.plist
sudo diskutil unmount disk0s1
```

Restart, then confirm what the kernel actually booted with:

```bash
sysctl kern.bootargs
```

A normal restart is enough on bare metal. In a VM you may need a cold boot, and
the EFI disk is mounted from the hypervisor host rather than from inside macOS.

If the argument still isn't in effect, OpenCore is skipping the write because
`boot-args` already exists in NVRAM — entries under `Add` are only applied when
the variable is absent. Check whether `boot-args` is listed under
`:NVRAM:Delete` for the same GUID, and add it there so the old value is cleared
before the new one is written.

### Should I re-enable SIP afterwards?

Yes. The extracted keys keep working — they're just files in `keys/`. Nothing
needs SIP off after extraction.

---

## Extraction

### Only `LocalStorage.key` was captured — the two `.bplist` files failed

The most common failure right now, and it is **not** a SIP/AMFI problem: getting
`LocalStorage.key` proves attaching works. Check the lldb log for:

```
KeyError: 'lldb_autogen_python_bp_callback_func__1'
```

That is a regression in **lldb 1700** (Xcode 16): installing a second Python
breakpoint callback from inside a running one crashes. Multiple people have hit
it. Check your version with `lldb --version` and say so in your issue.

### Keys go missing at random, with no error

Check whether **FindMySyncPlus is running**. It launches and kills the Find My
app on a timer to force a cache refresh, and this tool attaches to and kills the
same process — so the two fight, lldb sessions die mid-capture, and which keys
survive is luck. Quit FMS+ entirely (turning off its scheduler is not enough if
the app is still open) and run again. `extract.sh` now refuses to start when it
sees FMS+ running.

### Some keys captured, others not — and the Debug section is empty

An empty Debug block means nothing crashed; the run simply ended before Find My
read every key. Find My reads the two keychain items at *different moments*, so a
short wait can capture `FMFDataManager` and miss `FMIPDataManager` entirely.

Wait longer:

```bash
./extract.sh --wait 300
```

Slow or virtualised hardware routinely needs this — observed on a 2014 Mac mini
and reported independently from a Proxmox VM.

### `pip install` tries to compile `cryptography` and fails

`cryptography` needs a Rust toolchain to build from source, which most machines
don't have. Use `./extract.sh --setup`, which installs prebuilt wheels only and
fails immediately with a clear message if none exist for your Python. Python 3.11
or newer has the widest wheel coverage.

### Are the keys the same on my other Mac?

No. They're per-machine — extract on each Mac you want to sync from.

---

## Where the data lives

### Where is `LocalStorage.db`?

One of two places, and **which one is fixed when the store is first created and
never changes afterwards** — including across macOS upgrades:

```
$(getconf DARWIN_USER_DIR)com.apple.findmy.findmylocateagent/LocalStorage.db
~/Library/Group Containers/group.com.apple.findmy.findmylocateagent/Library/Application Support/LocalStorage.db
```

Two machines on the same macOS version can legitimately differ, so there is no
version rule — tools have to check both. `./diagnose.sh` reports which one you
have and which one the running agent has open.

### My `LocalStorage.db` is only 4 KB — is it empty?

Probably not. SQLite in WAL mode keeps recent content in the `-wal` file, so a
live database can have a tiny main file and a large `.db-wal` beside it. Judge it
by the pair, not the `.db` alone.

### Is my `Devices.data` encrypted?

`./diagnose.sh` reports it. Encrypted files are a property list containing an
`encryptedData` key; plaintext ones parse directly as a list of devices.

---

## Reporting a problem

Run `./diagnose.sh` and paste the whole output. It answers the questions we would
otherwise ask one at a time — macOS version, architecture, VM and OCLP detection,
SIP and AMFI state, lldb version, Python and dependencies, iCloud status, both
database locations, and which keys were captured.

It prints **no key material, no device names and no Apple ID**; your username is
replaced with `<user>` and the per-user `/var/folders` identifier is collapsed to
`<darwin>`. If extraction failed, include the lldb log too.
