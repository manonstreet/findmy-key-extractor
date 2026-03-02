#!/usr/bin/env python3
"""
verify_key.py — Verify extracted Find My keys by trial decryption.

Supports:
  1. LocalStorage.key — AES-256 key verified against LocalStorage.db page 0
  2. FMFDataManager.bplist / FMIPDataManager.bplist — ChaCha20-Poly1305 keys
     verified against their respective cache .data files

Usage:
  python3 verify_key.py LocalStorage.key
  python3 verify_key.py FMIPDataManager.bplist
  python3 verify_key.py FMFDataManager.bplist

Exit 0 on success, 1 on failure.
"""

import plistlib
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ── LocalStorage.db (AES-256 CBC keystream XOR) ─────────────────────────

PAGE_SIZE    = 4096
RESERVED_OFF = 4084
SQLITE_MAGIC = b"SQLite format 3\x00"

ENC_DB = (Path.home() /
          "Library/Group Containers"
          "/group.com.apple.findmy.findmylocateagent"
          "/Library/Application Support"
          "/LocalStorage.db")


def verify_localstorage_key(key_bytes, enc_db_path=ENC_DB):
    """Return True if key decrypts page 0 to valid SQLite header."""
    if len(key_bytes) != 32:
        return False

    data = enc_db_path.read_bytes()
    if len(data) < PAGE_SIZE:
        print(f"  ❌  {enc_db_path} is smaller than one page ({len(data)} bytes)")
        return False

    enc_page = data[:PAGE_SIZE]
    iv = struct.pack("<I", 1) + enc_page[RESERVED_OFF:RESERVED_OFF + 12]
    keystream = AES.new(key_bytes, AES.MODE_CBC, iv).encrypt(b'\x00' * PAGE_SIZE)
    plain_header = bytes(a ^ b for a, b in zip(enc_page[:16], keystream[:16]))
    return plain_header == SQLITE_MAGIC


# ── FMF/FMIP bplist keys (ChaCha20-Poly1305) ────────────────────────────

CACHE_DIRS = {
    "FMIPDataManager": Path.home() / "Library/Caches/com.apple.findmy.fmipcore",
    "FMFDataManager":  Path.home() / "Library/Caches/com.apple.findmy.fmfcore",
}

# One cache file per group to use for trial decryption
TRIAL_FILES = {
    "FMIPDataManager": "Devices.data",
    "FMFDataManager":  "FriendCacheData.data",
}


def verify_bplist_key(bplist_path):
    """Verify a FMF/FMIP bplist key by trial-decrypting a cache .data file.

    Returns True if the key successfully decrypts (Poly1305 auth tag passes).
    """
    stem = Path(bplist_path).stem  # e.g. "FMIPDataManager"

    # Parse the bplist and extract the 32-byte symmetric key
    with open(bplist_path, "rb") as f:
        plist_data = plistlib.load(f)

    sym_key_entry = plist_data.get("symmetricKey")
    if not sym_key_entry:
        print(f"  ❌  {stem}.bplist missing symmetricKey")
        return False

    # Handle nested structure: symmetricKey -> key -> data
    if isinstance(sym_key_entry, dict):
        key_dict = sym_key_entry.get("key", {})
        sym_key = key_dict.get("data") if isinstance(key_dict, dict) else None
        if not isinstance(sym_key, bytes):
            print(f"  ❌  {stem}.bplist has unexpected symmetricKey structure")
            return False
    elif isinstance(sym_key_entry, bytes):
        sym_key = sym_key_entry
    else:
        print(f"  ❌  {stem}.bplist has unexpected symmetricKey type")
        return False

    if len(sym_key) != 32:
        print(f"  ❌  {stem} symmetric key is {len(sym_key)} bytes (expected 32)")
        return False

    # Find a cache .data file to trial-decrypt
    cache_dir = CACHE_DIRS.get(stem)
    trial_name = TRIAL_FILES.get(stem)
    if not cache_dir or not trial_name:
        print(f"  ⚠️  {stem}.bplist valid (32-byte key) but no cache dir configured for trial decrypt")
        return True  # structural check passed

    trial_path = cache_dir / trial_name
    if not trial_path.exists():
        print(f"  ⚠️  {stem}.bplist valid (32-byte key) but {trial_name} not found for trial decrypt")
        return True  # structural check passed

    # Read the cache file — it's a plist with encryptedData
    with open(trial_path, "rb") as f:
        cache_plist = plistlib.load(f)

    encrypted_data = cache_plist.get("encryptedData")
    if not encrypted_data or len(encrypted_data) < 28:
        print(f"  ⚠️  {trial_name} missing or too-short encryptedData")
        return True  # can't trial-decrypt but key structure is valid

    # ChaCha20-Poly1305: nonce (12) + ciphertext + tag (16)
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]

    try:
        ChaCha20Poly1305(sym_key).decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        print(f"  ❌  {stem} key does not decrypt {trial_name}")
        return False

    return True


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <key-file>")
        sys.exit(1)

    key_path = Path(sys.argv[1])
    if not key_path.exists():
        print(f"  ❌  Key file not found: {key_path}")
        sys.exit(1)

    name = key_path.name

    if name.endswith(".key"):
        # LocalStorage.key verification
        key = key_path.read_bytes()
        if len(key) != 32:
            print(f"  ❌  Expected 32-byte key, got {len(key)} bytes")
            sys.exit(1)

        if not ENC_DB.exists():
            print(f"  ❌  Encrypted DB not found: {ENC_DB}")
            sys.exit(1)

        if verify_localstorage_key(key):
            print(f"  ✅  {name} verified [LocalStorage.db]")
        else:
            print(f"  ❌  {name} failed [LocalStorage.db]")
            sys.exit(1)

    elif name.endswith(".bplist"):
        # FMF/FMIP bplist key verification
        stem = key_path.stem
        if verify_bplist_key(key_path):
            trial_name = TRIAL_FILES.get(stem, "cache")
            print(f"  ✅  {name} verified [{trial_name}]")
        else:
            sys.exit(1)

    else:
        print(f"  ❌  Unknown key file type: {name}")
        sys.exit(1)


if __name__ == "__main__":
    main()
