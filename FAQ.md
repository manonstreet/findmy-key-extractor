# FAQ

Questions that have come up more than once. If you're stuck, run `./diagnose.sh`
first — it reports your environment and lists what's blocking you, and the output
is safe to paste into an issue.

---

## Setup: SIP and AMFI

### Do I really need to disable SIP?

Yes. The keys live in memory in Apple's own processes, and the only way to read
them is to attach a debugger — which SIP exists to prevent. Specifically you need
`ALLOW_TASK_FOR_PID`; without it `lldb` cannot attach and nothing else matters.

### `csrutil disable` says it worked, but `csrutil status` still shows restrictions

You're probably on **OpenCore** — an OpenCore Legacy Patcher Mac, or a VM booted
via OpenCore. OpenCore rewrites `csr-active-config` from its own `config.plist` on
every boot, so a change made in Recovery is silently reverted.

Change it in OpenCore instead:

- **OCLP:** open OpenCore-Patcher → Settings → **Security**, tick the SIP boxes,
  then **Build and Install OpenCore** and reboot.
- **Hand-edited OpenCore** (Proxmox and similar): edit `EFI/OC/config.plist` under
  `NVRAM → Add → 7C436110-AB2A-4BBB-A880-FE41995C9F82`, then cold boot.

### In OCLP, which SIP boxes do I tick?

**Tick all of them** (`0xFFF`). Do *not* build with the SIP value showing `0x0` —
that is SIP fully *enabled*, not "unchanged", and on an OCLP Mac it can break root
patching, because those patches need `ALLOW_UNAUTHENTICATED_ROOT`.

If you prefer the minimum: whatever your machine is booted with now, plus
`ALLOW_TASK_FOR_PID`. `ALLOW_UNRESTRICTED_NVRAM` is worth adding too — without it
`sudo nvram` refuses to set boot arguments.

### OCLP's "Disable AMFI" is ticked but AMFI still isn't disabled

Known: on some versions that checkbox doesn't produce a boot argument. Check what
is actually in effect:

```bash
sysctl kern.bootargs      # what the kernel booted with — authoritative
nvram boot-args           # what is stored — may differ
```

If `amfi_get_out_of_my_way` is missing, set it yourself, preserving the arguments
already there:

```bash
sudo nvram boot-args="<existing args> amfi_get_out_of_my_way=1"
```

then reboot. This needs `ALLOW_UNRESTRICTED_NVRAM` already set, or it fails with
`not permitted`.

### `sudo nvram` fails with `(iokit/common) not permitted`

NVRAM protection is still on. Add `ALLOW_UNRESTRICTED_NVRAM` to your SIP
configuration and reboot first.

### I set `boot-args` and after a reboot they're gone

OpenCore is managing them. Values under `NVRAM → Add` are **only written if the
variable does not already exist** — to change an existing one it must also be
listed under `NVRAM → Delete`. Set the argument in your OpenCore config (or the
OCLP Advanced tab) rather than with `nvram`.

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
