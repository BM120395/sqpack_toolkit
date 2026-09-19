"""Case study: SquashFS v4/xz tail-table diagnostics on UBI-hosted rootfs.

Self-contained, stdlib-only reference implementation of the lessons in
case_studies/README.md. NOT imported by any sqpack code path — read it, or run:

    python -m sqfs_repacker.case_studies.squashfs_tail_diagnostics image.squashfs

Functions are deliberately independent of the sqpack internals so future
releases can lift them without coupling.

Key techniques demonstrated:
  walk_xz_containers()    — magic+footer metadata walk (size-word independent)
  decode_stream()         — tolerant xz decode with CLI-first fallback notes
  triangulate()           — failure-stage comparison across two image views
  partial_inventory()     — extract structural evidence from partial decodes
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import zlib
from typing import Dict, List, Optional, Tuple

XZ_MAGIC = b"\xfd7zXZ\x00"


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


# ----------------------------------------------------------- xz container walk

def walk_xz_containers(data: bytes, start: int, end: int) -> List[Dict]:
    """Locate xz containers by magic, validate block-header + index CRCs, and
    hop to the next stream — independent of (possibly padded) size words.

    Each entry: {offset, bhdr_crc_ok, index_crc_ok, footer_ok, next}.
    """
    out = []
    pos = start
    while pos + 12 <= end:
        m = data.find(XZ_MAGIC, pos, end)
        if m < 0:
            break
        entry = {"offset": m, "bhdr_crc_ok": None, "index_crc_ok": None,
                 "footer_ok": None, "next": None}
        # Block header starts AFTER the 12-byte stream header (magic 6 +
        # flags 2 + CRC32 4). Byte 0 = header_size/4 - 1; CRC32 is the LAST
        # 4 bytes, computed over ALL preceding header bytes.
        hb = m + 12
        hsz = (data[hb] + 1) * 4
        bh = data[hb:hb + hsz]
        if len(bh) == hsz and hsz >= 8:
            stored = _u32(bh, hsz - 4)
            calc = zlib.crc32(bh[:hsz - 4]) & 0xFFFFFFFF
            entry["bhdr_crc_ok"] = (stored == calc)
        # Find the index: xz index indicator 0x00 followed by records; the
        # stream footer is a 12-byte block with CRC32 over its last 6 bytes.
        tail = data[m:end]
        fi = tail.rfind(b"\x59Z")  # footer magic 'YZ' at footer+4
        if fi >= 0:
            f = tail[fi - 2:fi - 2 + 12]
            if len(f) == 12:
                stored = _u32(f, 0)
                calc = zlib.crc32(f[4:10]) & 0xFFFFFFFF
                entry["footer_ok"] = (stored == calc)
                entry["next"] = m + fi - 2 + 12
        out.append(entry)
        pos = m + 12
    return out


# ------------------------------------------------------------- tolerant decode

def decode_stream(data: bytes, off: int, max_out: int = 1 << 20) -> Tuple[int, int]:
    """Decode one xz stream starting at off via the CLI (single-stream mode).
    Returns (decoded_bytes, max_out). CLI-first: on vendor streams the CLI
    accepts some streams python-lzma rejects; a stream that dies mid-payload
    still yields partial output — structural evidence, not garbage."""
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "s.xz")
        with open(src, "wb") as f:
            f.write(data[off:off + (1 << 20)])
        try:
            r = subprocess.run(["xz", "-dc", "--single-stream", src],
                               capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return 0, 0
        return len(r.stdout), max_out


def partial_inventory(data: bytes, offsets: List[int]) -> List[Dict]:
    """Structural evidence from partially-decoded metadata: report decoded
    size and a printable/ELF/inode-head classification of the first bytes."""
    inv = []
    for off in offsets:
        n, _ = decode_stream(data, off)
        head = data[off + 12:off + 12 + 4]
        kind = "other"
        if head[:4] == b"\x7fELF":
            kind = "elf"
        elif head[:1] == b"\x00" or head[:1] in b"1234":
            kind = "likely-inode/dir"
        inv.append({"offset": off, "decoded": n, "head": head.hex(), "kind": kind})
    return inv


# ------------------------------------------------------- failure triangulation

def failure_stage(image_path: str, unsquashfs: str = "unsquashfs") -> str:
    """Run unsquashfs and classify the failure stage from its stderr."""
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([unsquashfs, "-d", os.path.join(td, "o"), "-no-progress",
                            image_path], capture_output=True, text=True, timeout=120)
        err = r.stderr + r.stdout
        for stage, pat in (
            ("superblock", "Superblock"),
            ("id_table", "read_id_table"),
            ("fragment_table", "read_fragment_table"),
            ("inode", "read_inode"),
            ("data", "read_data"),
        ):
            if pat in err:
                return stage
        return "ok" if r.returncode == 0 else "unknown"


def triangulate(view_a: str, view_b: str,
                unsquashfs: str = "unsquashfs") -> Dict[str, str]:
    """Compare failure stages of two views of the same filesystem. Different
    stages (e.g. id_table vs fragment_table) prove the tail bytes differ —
    one view is mis-assembled. Identical stages point at shared damage."""
    return {"view_a": failure_stage(view_a, unsquashfs),
            "view_b": failure_stage(view_b, unsquashfs)}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    data = open(sys.argv[1], "rb").read()
    containers = walk_xz_containers(data, 0, min(len(data), 1 << 24))
    print(f"xz containers found: {len(containers)}")
    clean = sum(1 for c in containers if c["bhdr_crc_ok"])
    print(f"block-header CRC valid: {clean}/{len(containers)}")
    offs = [c["offset"] for c in containers[:8]]
    for row in partial_inventory(data, offs):
        print(row)
