#!/usr/bin/env python3
"""
PE post-processor for DungeonMaster agent binaries.

Applies two modifications that reduce static-analysis fingerprinting:
  1. Zero the Rich Header (removes compiler/linker toolchain fingerprint)
  2. Set a realistic PE timestamp (avoids "compiled 5 seconds ago" heuristic)

Usage:
    python pe_patch.py dm-agent.exe [--timestamp 2025-03-14]
    python pe_patch.py dm-agent.exe --inplace
"""

import argparse
import os
import struct
import sys
from datetime import datetime, timezone


def patch_pe(data: bytearray, fake_ts: int) -> bytearray:
    # ── 1. Verify MZ magic ────────────────────────────────────────────────────
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("PE signature not found")

    # ── 2. Patch the PE timestamp (COFF header offset +8 from PE sig) ─────────
    ts_offset = e_lfanew + 8
    struct.pack_into("<I", data, ts_offset, fake_ts)

    # ── 3. Zero the Rich Header ───────────────────────────────────────────────
    # The Rich Header sits between the DOS stub and the PE header, bounded by
    # "DanS" (beginning, XOR'd) and "Rich" (terminator).  Finding it:
    #   - "Rich" signature is at some offset before e_lfanew
    #   - The 4-byte XOR key immediately follows "Rich"
    #   - XOR key applied to "DanS" gives the start marker
    rich_tag = b"Rich"
    rich_off = data.find(rich_tag, 0x40, e_lfanew)
    if rich_off != -1:
        # The 4-byte key is right after "Rich"
        xor_key = struct.unpack_from("<I", data, rich_off + 4)[0]
        dans_enc = xor_key ^ struct.unpack_from("<I", b"DanS")[0]
        dans_enc_bytes = struct.pack("<I", dans_enc)
        dans_off = data.find(dans_enc_bytes, 0x40, rich_off)
        if dans_off != -1:
            # Zero everything from DanS through the end of "Rich" + key (8 bytes)
            end = rich_off + 8
            for i in range(dans_off, end):
                data[i] = 0

    return data


def main():
    parser = argparse.ArgumentParser(description="DM agent PE patcher")
    parser.add_argument("input", help="Path to compiled agent .exe")
    parser.add_argument("--output", "-o", help="Output path (default: input.patched.exe)")
    parser.add_argument(
        "--timestamp", "-t",
        default="2025-03-14",
        help="Fake build date in YYYY-MM-DD format (default: 2025-03-14)",
    )
    parser.add_argument(
        "--inplace", action="store_true",
        help="Overwrite the input file instead of writing a new one",
    )
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = bytearray(f.read())

    try:
        ts_date = datetime.strptime(args.timestamp, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        print(f"[!] Invalid date format: {args.timestamp}  (expected YYYY-MM-DD)")
        sys.exit(1)

    fake_ts = int(ts_date.timestamp())

    print(f"[*] Input : {args.input} ({len(data):,} bytes)")
    print(f"[*] Timestamp => {args.timestamp} (0x{fake_ts:08X})")

    data = patch_pe(data, fake_ts)

    if args.inplace:
        out_path = args.input
    else:
        base, ext = os.path.splitext(args.input)
        out_path = args.output or (base + ".patched" + ext)

    with open(out_path, "wb") as f:
        f.write(data)

    print(f"[+] Written: {out_path}")


if __name__ == "__main__":
    main()
