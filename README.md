# findmy-key-extractor

![macOS](https://img.shields.io/badge/macOS-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white)

> Extract all three Apple Find My encryption keys in a single run. Once extracted, keys are stable across reboots.

Used by [FindMySyncPlus](https://github.com/manonstreet/FindMySyncPlus) to decrypt Find My data and publish device, item, and friend locations to Home Assistant.

| Key file | Protects | Encryption |
|----------|----------|------------|
| `LocalStorage.key` | Friend locations (`LocalStorage.db`) | AES-256 keystream XOR |
| `FMIPDataManager.bplist` | Devices, items, family members (FMIP cache) | ChaCha20-Poly1305 |
| `FMFDataManager.bplist` | Friend metadata (FMF cache) | ChaCha20-Poly1305 |

## Prerequisites

- macOS (Apple Silicon and Intel x86_64)

### Tested configurations

| macOS | arch | lldb | result |
|---|---|---|---|
| 15.7.2 | Intel (OCLP) | 1700 (Command Line Tools) | all three keys |
| 26.5.2 | Apple Silicon | 1703 (Xcode) | all three keys |
| 26.5.2 | Apple Silicon | 2100 (Command Line Tools) | all three keys |
| 15.7 | Apple Silicon | 1703 | **reported failing** ([#10](https://github.com/manonstreet/findmy-key-extractor/issues/10)) |

**Which lldb runs matters, and it is not always the obvious one.**
`/usr/bin/lldb` is a shim that forwards to whatever `xcode-select -p` points at,
so Xcode and the Command Line Tools can supply different builds on the same Mac.
Every run prints the one it used; `./diagnose.sh` lists all of them and which is
active. Include that in any bug report.
- Xcode Command Line Tools — `xcode-select --install` (provides lldb)
- Python 3 + pip
- Find My app installed and signed into iCloud

> [!WARNING]
> This procedure requires temporarily disabling macOS security features (SIP + AMFI). You will re-enable them in Step 3.

## Quick Start

### Step 1: Disable SIP + AMFI

lldb cannot attach to Apple platform binaries under normal security settings.

Boot into macOS Recovery:

- **Apple Silicon**: Shut down, hold power button until "Loading startup options", select Options
- **Intel**: Restart, hold Cmd+R until Apple logo appears

In the Recovery terminal:

```bash
csrutil disable
```

Reboot into macOS, then add the AMFI boot argument:

```bash
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```

Reboot again. Verify:

```bash
csrutil status          # should show "disabled"
nvram boot-args         # should show amfi_get_out_of_my_way=1
```

### Step 2: Extract Keys

```bash
cd findmy-key-extractor
./extract.sh --setup   # one-time: virtualenv in .venv + pycryptodome, cryptography
./extract.sh           # add --wait 300 on slow or virtualised machines
```

`--setup` is opt-in rather than automatic: this script runs `sudo lldb` against
system processes on a machine with SIP disabled, so it doesn't fetch anything
from PyPI unless you ask it to. Nothing outside `.venv` is touched, and later
runs pick that up without it being activated.

Prefer to do it yourself:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

A virtualenv rather than a plain `pip3 install` because it works whichever
`python3` you have — Apple's permits a direct install, Homebrew's refuses it
(`externally-managed-environment`).

Apart from the password prompt there's no interaction. The script launches two
parallel lldb sessions, restarts the Find My processes to trigger key loading,
captures the keys, and verifies each one. A typical run takes 25–40 seconds; it
waits up to 180 for Find My to ask for its keys, and retries if it doesn't:

```
  🔑  Find My Key Extractor
  ─────────────────────────

  Administrator access is required. macOS will prompt for your login
  password next — that prompt comes from macOS, not from this script,
  and the password is never stored or sent anywhere.

  It is used for:
    • lldb          attach to the Find My app to read its keys
    • pkill         restart Find My so it re-reads them
    • chown         make the captured key files readable by you

Password:

  ⏳  Waiting for Find My to read its keys (up to 180s)...

  ── Extraction ──

  ✅  LocalStorage.key (32 bytes)
  ✅  FMFDataManager.bplist (171 bytes)
  ✅  FMIPDataManager.bplist (171 bytes)

  ── Verification ──

  ✅  LocalStorage.key verified [LocalStorage.db]
  ✅  FMIPDataManager.bplist verified [Devices.data]
  ✅  FMFDataManager.bplist verified [FriendCacheData.data]

  💾 Saved to ./keys/
```

Keys are saved to `./keys/` (re-running overwrites existing files with identical keys). Keep these files safe — after re-enabling SIP you'll need to repeat the full procedure to extract them again.

### Step 3: Re-enable Security

Reverse the change wherever you made it in Step 1.

**On a stock Mac** — boot into macOS Recovery and run:

```bash
nvram -d boot-args
csrutil enable
```

**On an OpenCore machine (OCLP, or a VM booted via OpenCore)** — do it in
OpenCore, not Recovery. OpenCore rewrites both values from its own `config.plist`
on every boot, so a change made in Recovery is silently reverted and you will
believe SIP is back on when it is not. Untick the SIP boxes in
OpenCore-Patcher → Settings → **Security** and rebuild, or remove
`amfi_get_out_of_my_way=1` from `boot-args` and restore `csr-active-config` in
`config.plist`.

Reboot, then confirm both actually took:

```bash
csrutil status          # should no longer say "disabled"
sysctl kern.bootargs    # should no longer contain amfi_get_out_of_my_way
```

The extracted keys continue to work — they are just files in `keys/`.

## Troubleshooting

**If something fails, run `./diagnose.sh` first.** It reports SIP and AMFI state,
your lldb version, and where the Find My files are, then names whatever is
blocking extraction. It is also the output to attach to a bug report.

Longer answers to recurring questions — SIP on OpenCore/OCLP machines, AMFI boot
arguments, partial key capture, where `LocalStorage.db` lives — are in [FAQ.md](FAQ.md).


| Problem | Fix |
|---------|-----|
| `error: attach failed` | SIP/AMFI not fully disabled. Try `csrutil disable` (full) in Recovery. |
| Extraction hangs | Find My may not have launched. Check if it's running: `pgrep -x FindMy`. |
| `pip3: command not found` | Install Python 3: `brew install python3` or use `python3 -m pip`. |
| `error: externally-managed-environment` | Your `python3` is PEP 668-managed (Homebrew's unversioned `python`, pyenv, …). Run `./extract.sh --setup` rather than `--break-system-packages`. |
| `ModuleNotFoundError: No module named 'Crypto'` | Dependencies missing for the interpreter in use. Run `./extract.sh --setup`; the script also checks this before extracting. |

## Files

| File | Purpose |
|------|---------|
| `extract.sh` | Main script — orchestrates parallel key extraction |
| `extract_db_key.py` | lldb breakpoint handler for `sqlite3_key_v2` |
| `extract_keychain_keys.py` | lldb breakpoint handler for `SecItemCopyMatching` |
| `verify_key.py` | Standalone key verifier — trial decryption |
| `decrypt_localstorage.py` | Optional CLI decryptor for LocalStorage.db |
| `requirements.txt` | Python dependencies |
| `diagnose.sh` | Environment report — run this first when something fails |
| `FAQ.md` | Setup problems, partial captures, where the data lives |

The commands below call `python3` directly, unlike `extract.sh` — use
`.venv/bin/python3` in place of `python3`, or activate the virtualenv first.

You can re-verify keys at any time (no SIP disable needed):

```bash
python3 verify_key.py keys/LocalStorage.key
python3 verify_key.py keys/FMIPDataManager.bplist
python3 verify_key.py keys/FMFDataManager.bplist
```

### CLI Decryption

**LocalStorage.db** — decrypt to a plain SQLite file you can open with any SQLite browser:

```bash
python3 decrypt_localstorage.py keys/LocalStorage.key
# → LocalStorage_decrypted.sqlite
```

Applies WAL frames automatically if present. Use `-o` for a custom output path or `--db` to point to a non-default database location.

**Cache files** (Devices.data, Items.data, FriendCacheData.data) — use [findmy-cache-decryptor](https://github.com/Pnut-GGG/findmy-cache-decryptor) with the FMIP/FMF keys.

---

## Technical Deep Dive

### How It Works

`extract.sh` orchestrates two parallel lldb sessions against two processes:

```
extract.sh
  ├── lldb --wait-for findmylocateagent    (extract_db_key.py)
  │     └── breakpoint: sqlite3_key_v2  →  LocalStorage.key
  │
  ├── lldb --wait-for FindMy               (extract_keychain_keys.py)
  │     └── breakpoint: SecItemCopyMatching
  │           ├── svce = "FMIPDataManager"  →  FMIPDataManager.bplist
  │           └── svce = "FMFDataManager"   →  FMFDataManager.bplist
  │
  ├── open FindMy.app                      (triggers both processes)
  └── wait + verify
```

Both sessions run in the background. After Find My launches, both processes start and hit their breakpoints within seconds. A typical run takes 25–40 seconds end to end, most of it waiting for Find My to ask for its keys.

#### LocalStorage.key — `sqlite3_key_v2`

`findmylocateagent` opens its encrypted databases by calling:

```c
sqlite3_key_v2(db, "main", key, 32)
```

The lldb script detects the target architecture via `target.GetTriple()` and reads the appropriate calling convention registers:

| Argument | ARM64 (AAPCS64) | x86_64 (System V AMD64) | Value |
|----------|-----------------|-------------------------|-------|
| 0 | `x0` | `rdi` | `sqlite3 *db` — database handle |
| 1 | `x1` | `rsi` | `"main"` — schema name (always "main") |
| 2 | `x2` | `rdx` | `const void *key` — pointer to 32-byte key |
| 3 | `x3` | `rcx` | `32` — key length |

It then calls `sqlite3_db_filename(db, "main")` to identify which database this key belongs to. When the path contains `LocalStorage`, the 32-byte key is saved and the process is killed.

#### FMF/FMIP keys — `SecItemCopyMatching`

`FindMy.app` reads keychain items via `SecItemCopyMatching(query, &result)`. The
lldb script uses a two-phase approach:

1. **Entry breakpoint**: reads `svce` from the query dictionary to identify which
   item is being fetched, and records the result pointer (arg 1) and the return
   address (stripped of PAC bits on ARM64).
2. **Return breakpoint**: armed with a **condition** — a C/ObjC expression, built
   for this specific call, that performs the entire capture and then evaluates to
   `0` so the breakpoint never actually stops.

The condition dereferences the result pointer, walks the `NSDictionary` to
`v_Data` (the raw keychain value), and writes those bytes to a file named after
`svce`.

#### Why a condition, and why it writes inside the app

The capture runs as a condition rather than as a Python callback because on
lldb 1700 (Xcode 16) installing a Python breakpoint callback from *inside* another
one fails with `KeyError: lldb_autogen_python_bp_callback_func__N`. Conditions are
evaluated by lldb's own expression evaluator with no Python involved, so they
sidestep it entirely.

Because the condition executes inside `FindMy.app`, it runs under that process's
**App Sandbox**. A plain `open()` to an arbitrary path silently fails there — SIP
and AMFI being relaxed lets us attach and set breakpoints, but the sandbox is a
separate per-process kernel policy that injected code still runs under. So the
condition writes to `NSTemporaryDirectory()`, which resolves to the app's own
writable container:

```
~/Library/Containers/com.apple.findmy/Data/tmp/
```

`extract.sh` polls that directory and copies each `.bplist` out to `./keys/` as
it appears, running as the normal unsandboxed user. Once both keys are out, the
process is killed.

One consequence worth knowing if you are modifying this: **a condition that
errors counts as a stop**, which ends the batch-mode lldb session and loses any
key not yet captured. The condition therefore builds its output path first and
returns early once that file exists, so after a successful capture it dereferences
nothing.

### Encryption Schemes

#### LocalStorage.db — AES-256 Keystream XOR

Apple's `sqliteCodecCCCrypto` encrypts each 4096-byte SQLite page independently. This was confirmed by disassembly of the codec within `libsqlite3.dylib` (functions `sqliteCodecCCCrypto`, `loadKeyCCCrypt`).

**Page layout:**

```
     0                                          4084    4096
     ┌──────────────────────────────────────────┬───────────┐
     │          encrypted content               │  reserved │
     │             4084 bytes                   │  12 bytes │
     │        (XOR'd with keystream)            │(plaintext)│
     └──────────────────────────────────────────┴─────┬─────┘
                                                      │
                      ┌───────────────────────────────┘
                      ▼
              ┌────────────────┐
              │  IV (16 bytes) │
              │ ┌────────────┐ │
              │ │pgno LE32(4)│ │    pgno = page_index + 1
              │ ├────────────┤ │
              │ │reserved(12)│ │    from bytes 4084-4095
              │ └────────────┘ │
              └───────┬────────┘
                      ▼
     AES-256-CBC-ENCRYPT(key, IV, zeros[4096])
                      ▼
                  keystream
                      ▼
     plaintext = encrypted[0:4084] ⊕ keystream[0:4084]
```

This is **not** standard CBC decryption. The cipher generates a keystream by CBC-*encrypting* zeros, then XORs the keystream against the page content — a CTR-like construction.

**Page 0 special case:** bytes 16–23 contain SQLite header constants stored in plaintext (`page_size`, `format_versions`, `reserved_space`). After XOR decryption, restore these bytes from the original encrypted page:

```
Page 0 fix-up:  plaintext[16:24] = enc_page[16:24]
```

**Verification:** page 0 decrypts to `SQLite format 3\0` in the first 16 bytes.

#### Cache Files — ChaCha20-Poly1305

The bplist key files contain a nested symmetric key:

```
┌─ FMIPDataManager.bplist ────────┐
│ symmetricKey:                   │
│   └─ key:                       │
│       └─ data: <32 bytes>  ◄───── ChaCha20-Poly1305 key
└─────────────────────────────────┘
```

Each cache `.data` file is a binary plist with an `encryptedData` blob:

```
     0           12                              len-16    len
     ┌───────────┬──────────────────────────────┬──────────┐
     │   nonce   │         ciphertext           │Poly1305  │
     │ (12 bytes)│                              │  tag     │
     │           │                              │(16 bytes)│
     └───────────┴──────────────────────────────┴──────────┘

     plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext‖tag, aad=None)
```

The Poly1305 tag provides cryptographic integrity — wrong key raises an exception, making false positives impossible.

Decrypted plaintext is typically a binary plist (`bplist00` header) containing device locations, friend data, or other Find My state.

### Why lldb?

Under normal macOS security, all three keys are protected by Keychain ACLs restricting access to Apple-signed binaries with specific `keychain-access-group` entitlements. Extraction requires SIP/AMFI disabled in all cases (`findmylocateagent` is a `CS_PLATFORM_BINARY`).

**FMIP/FMF keychain keys** can also be extracted by a custom app signed with spoofed entitlements — an approach pioneered by [airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor) (Stute et al., USENIX Security 2019) and adapted for Find My by [FMIPDataManager-extractor](https://github.com/Pnut-GGG/FMIPDataManager-extractor). That approach works well for the 2 keychain-based keys.

**LocalStorage.key** is different. The key is in the keychain, but its ACL requires the `CS_PLATFORM_BINARY` flag — a kernel-level property of Apple-signed system binaries that cannot be spoofed, even with SIP/AMFI disabled and entitlement tricks. No third-party binary can query it. The only extraction path is lldb: attach to `findmylocateagent` as it passes the key in-memory to `sqlite3_key_v2(db, "main", key, 32)`, and read it from registers at the call site.

This tool uses lldb for all 3 keys — capturing them in a single parallel run without requiring an Xcode project or signing setup. The keys are stable (derived from your iCloud account), so extraction only needs to happen once.

## Credits

- Entitlement spoofing technique: [airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor) by Milan Stute et al. ([USENIX Security 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/stute)), adapted for Find My by [FMIPDataManager-extractor](https://github.com/Pnut-GGG/FMIPDataManager-extractor)
- Cache decryption: [findmy-cache-decryptor](https://github.com/Pnut-GGG/findmy-cache-decryptor)
- 🤖 LocalStorage.db cipher: reverse-engineered from `sqliteCodecCCCrypto` disassembly by manonstreet & [Claude](https://claude.ai)

## Disclaimer

This tool accesses your own data on your own machine using your own credentials. It provides programmatic access to the same information already visible to you in the Find My app. It is intended for personal use, interoperability, and research. Use responsibly and in accordance with applicable laws.
