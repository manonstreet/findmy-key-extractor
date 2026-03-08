#!/usr/bin/env python3
"""
decrypt_localstorage.py — Decrypt Apple Find My LocalStorage.db to plain SQLite.

Usage:
  python3 decrypt_localstorage.py keys/LocalStorage.key
  python3 decrypt_localstorage.py keys/LocalStorage.key -o friends.sqlite

Reads the encrypted LocalStorage.db (and .db-wal if present) from the default
Find My location, decrypts all pages, and writes a standard SQLite file.

Exit 0 on success, 1 on failure.
"""

import argparse
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES

PAGE_SIZE = 4096
RESERVED_OFF = 4084
RESERVED_LEN = 12
CONTENT_LEN = RESERVED_OFF  # 4084 encrypted bytes per page
SQLITE_MAGIC = b"SQLite format 3\x00"

FINDMY_CONTAINER = (
    Path.home()
    / "Library/Group Containers"
    / "group.com.apple.findmy.findmylocateagent"
    / "Library/Application Support"
)
ENC_DB = FINDMY_CONTAINER / "LocalStorage.db"
ENC_WAL = FINDMY_CONTAINER / "LocalStorage.db-wal"

WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def decrypt_page(key: bytes, page_data: bytes, page_index: int) -> bytes:
    """Decrypt a single 4096-byte page using AES-256-CBC keystream XOR."""
    pgno = page_index + 1
    reserved = page_data[RESERVED_OFF:RESERVED_OFF + RESERVED_LEN]
    iv = struct.pack("<I", pgno) + reserved
    keystream = AES.new(key, AES.MODE_CBC, iv).encrypt(b"\x00" * PAGE_SIZE)
    decrypted = bytes(a ^ b for a, b in zip(page_data[:CONTENT_LEN], keystream[:CONTENT_LEN]))
    result = decrypted + reserved

    # Page 0 fix-up: bytes 16-23 are stored in plaintext in the encrypted page
    if page_index == 0:
        result = result[:16] + page_data[16:24] + result[24:]

    return result


def decrypt_db(key: bytes, db_path: Path) -> bytearray:
    """Decrypt all pages in the database file."""
    data = db_path.read_bytes()
    num_pages = len(data) // PAGE_SIZE
    if num_pages == 0:
        print(f"  Error: {db_path} is empty")
        sys.exit(1)

    output = bytearray()
    for i in range(num_pages):
        page = data[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]
        output.extend(decrypt_page(key, page, i))

    # Verify page 0
    if output[:16] != SQLITE_MAGIC:
        print("  Error: decryption failed — page 0 does not contain SQLite header")
        print("         (wrong key or corrupted database)")
        sys.exit(1)

    return output


def apply_wal(key: bytes, wal_path: Path, db_pages: bytearray) -> bytearray:
    """Apply WAL frames on top of the decrypted database."""
    wal_data = wal_path.read_bytes()
    if len(wal_data) < WAL_HEADER_SIZE:
        return db_pages

    offset = WAL_HEADER_SIZE
    applied = 0
    while offset + WAL_FRAME_HEADER_SIZE + PAGE_SIZE <= len(wal_data):
        # Frame header: pgno (4 bytes big-endian) at offset 0
        pgno = struct.unpack(">I", wal_data[offset:offset + 4])[0]
        frame_page = wal_data[offset + WAL_FRAME_HEADER_SIZE:offset + WAL_FRAME_HEADER_SIZE + PAGE_SIZE]
        page_index = pgno - 1
        decrypted = decrypt_page(key, frame_page, page_index)

        # Extend db if WAL references pages beyond current size
        needed = (page_index + 1) * PAGE_SIZE
        if needed > len(db_pages):
            db_pages.extend(b"\x00" * (needed - len(db_pages)))

        db_pages[page_index * PAGE_SIZE:(page_index + 1) * PAGE_SIZE] = decrypted
        applied += 1
        offset += WAL_FRAME_HEADER_SIZE + PAGE_SIZE

    if applied > 0:
        print(f"  Applied {applied} WAL frames")

    return db_pages


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt Apple Find My LocalStorage.db to plain SQLite"
    )
    parser.add_argument("key_file", type=Path, help="Path to LocalStorage.key (32 bytes)")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="Output path (default: LocalStorage_decrypted.sqlite)")
    parser.add_argument("--db", type=Path, default=None,
                        help=f"Path to encrypted LocalStorage.db (default: {ENC_DB})")
    args = parser.parse_args()

    # Read key
    if not args.key_file.exists():
        print(f"  Error: key file not found: {args.key_file}")
        sys.exit(1)

    key = args.key_file.read_bytes()
    if len(key) != 32:
        print(f"  Error: expected 32-byte key, got {len(key)} bytes")
        sys.exit(1)

    # Locate database
    db_path = args.db or ENC_DB
    if not db_path.exists():
        print(f"  Error: database not found: {db_path}")
        sys.exit(1)

    output_path = args.output or Path("LocalStorage_decrypted.sqlite")

    # Decrypt
    print(f"  Decrypting {db_path.name}...")
    result = decrypt_db(key, db_path)

    # Apply WAL if present
    wal_path = args.db.parent / (args.db.name + "-wal") if args.db else ENC_WAL
    if wal_path.exists() and wal_path.stat().st_size > WAL_HEADER_SIZE:
        print(f"  Applying {wal_path.name}...")
        result = apply_wal(key, wal_path, result)

    # Write output
    output_path.write_bytes(result)
    print(f"  Wrote {output_path} ({len(result):,} bytes)")


if __name__ == "__main__":
    main()
