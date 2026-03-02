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

- macOS (Apple Silicon or Intel)
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
pip3 install -r requirements.txt   # one-time: pycryptodome + cryptography
./extract.sh
```

No interaction needed. The script kills Find My, launches two parallel lldb sessions, reopens Find My to trigger key loading, captures the keys, and verifies each one:

```
  🔑  Find My Key Extractor
  ─────────────────────────

  ⏳  Extracting keys (~10s)...

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

Boot into macOS Recovery and run:

```bash
nvram -d boot-args
csrutil enable
```

Reboot. Your Mac is back to its normal security posture. The extracted keys continue to work.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `error: attach failed` | SIP/AMFI not fully disabled. Try `csrutil disable` (full) in Recovery. |
| Extraction hangs | Find My may not have launched. Check if it's running: `pgrep -x FindMy`. |
| `findmylocateagent` not found | Open Find My at least once — the agent only starts after first launch. |
| Key verification fails | Find My cache may be stale. Open Find My, wait for it to refresh, re-run. |
| `pip3: command not found` | Install Python 3: `brew install python3` or use `python3 -m pip`. |

## Files

| File | Purpose |
|------|---------|
| `extract.sh` | Main script — orchestrates parallel key extraction |
| `extract_db_key.py` | lldb breakpoint handler for `sqlite3_key_v2` |
| `extract_keychain_keys.py` | lldb breakpoint handler for `SecItemCopyMatching` |
| `verify_key.py` | Standalone key verifier — trial decryption |
| `requirements.txt` | Python dependencies |

You can re-verify keys at any time (no SIP disable needed):

```bash
python3 verify_key.py keys/LocalStorage.key
python3 verify_key.py keys/FMIPDataManager.bplist
python3 verify_key.py keys/FMFDataManager.bplist
```

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
  ├── open "Find My.app"                   (triggers both processes)
  └── wait + verify
```

Both sessions run in the background. After Find My launches, both processes start and hit their breakpoints within seconds. Total runtime is ~10s.

#### LocalStorage.key — `sqlite3_key_v2`

`findmylocateagent` opens its encrypted databases by calling:

```c
sqlite3_key_v2(db, "main", key, 32)
```

The lldb script reads AArch64 calling convention registers on the breakpoint:

| Register | Value |
|----------|-------|
| `x0` | `sqlite3 *db` — database handle |
| `x1` | `"main"` — schema name (always "main") |
| `x2` | `const void *key` — pointer to 32-byte key |
| `x3` | `32` — key length |

It then calls `sqlite3_db_filename(db, "main")` to identify which database this key belongs to. When the path contains `LocalStorage`, the 32-byte key is saved and the process is killed.

#### FMF/FMIP keys — `SecItemCopyMatching`

`FindMy.app` reads keychain items via `SecItemCopyMatching(query, &result)`. The lldb script uses a two-phase approach:

1. **Entry breakpoint**: Records the result pointer (`x1`) and return address (`lr` with PAC bits stripped via `& 0x000000FFFFFFFFFF`)
2. **Return breakpoint**: One-shot breakpoint at the return address. Checks `x0 == 0` (success), then reads the result `NSDictionary`

From the dictionary, it extracts:
- `svce` — service name (e.g., `"FMIPDataManager"`) → used as output filename
- `v_Data` — raw keychain value data → saved as `{svce}.bplist`

After capturing 2 items (FMF + FMIP), the process is killed.

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
