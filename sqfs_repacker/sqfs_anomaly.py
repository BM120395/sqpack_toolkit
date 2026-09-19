"""Anomaly engine for sqfs-repacker: bit-rot detection/repair for SquashFS
images. Ported from the ubi-toolkit anomaly engine (v1.6.0 semantics).

SQANOM-1 -- bit rot vs --reference
    SquashFS stores no per-block CRCs; the only integrity anchors are the
    compressed stream boundaries themselves. When a known-good reference
    image exists, differences are classified as:

        bit rot    : low total rate (<1%), overwhelmingly single-bit bytes,
                     no long contiguous runs (a layout bug produces runs;
                     NAND rot produces isolated single-byte hits)
        layout bug : anything else (NOT auto-repaired -- reported fatal)

    Single-bit bytes are repaired in place against the reference
    (evidence-gated: only bytes at Hamming distance 1 are touched);
    multi-bit bytes are left for the user. Exit-code contract mirrors
    ubipack: repairable anomaly without --yes/--auto-consent -> exit 3
    fail-fast with a rerun hint; --yes applies repairs and continues.

SQANOM-2 -- structural integrity (reference-free)
    Superblock-driven checks: truncated file (bytes_used > size), table
    pointers outside the image, zero inodes, unknown compression id.
    Findings style matches analyzer.integrity_findings.

All pure stdlib, same as the rest of the toolkit.
"""
from __future__ import annotations

import zlib
from typing import Dict, List, Optional, Tuple

# Chunked int-XOR window (C-speed over the common all-zero chunks).
BITROT_MAX_CHUNK = 1 << 20
BITROT_BIT_CAP = 1 << 22

XZ_MAGIC = b"\xfd7zXZ\x00"
GZ_MAGIC = b"\x1f\x8b"
LZMA_MAGIC = b"\x5d\x00\x00"
SQFS_MAGIC_BYTES = b"hsqs"


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


# ---------------------------------------------------------------------------
# SQANOM-1: bit rot classification + repair (ported from ubi anomaly engine)
# ---------------------------------------------------------------------------
def bitrot_signature(volume: bytes, reference: bytes, block: int = 512
                     ) -> Dict:
    """Classify image-vs-reference differences as bit rot or a layout bug.

    Healthy rot: total rate << 1%, overwhelmingly single-bit bytes, and no
    long contiguous runs of differing bytes (a layout shift produces runs;
    bit rot produces isolated single-byte hits)."""
    n = min(len(volume), len(reference))
    diff_bytes = 0
    flip_bits = 0
    multi_bit_bytes = 0
    max_run = 0
    run = 0
    for base in range(0, n, BITROT_MAX_CHUNK):
        chunk_v = volume[base:base + BITROT_MAX_CHUNK]
        # reference may be longer than the volume (e.g. tail padding):
        # slice per-chunk so the int-XOR lengths always match
        chunk_r = reference[base:base + len(chunk_v)]
        xi = int.from_bytes(chunk_v, "little") ^ int.from_bytes(chunk_r,
                                                                "little")
        if xi == 0:
            run = 0
            continue
        cb = xi.to_bytes(len(chunk_v), "little")
        for i, d in enumerate(cb):
            if d:
                diff_bytes += 1
                h = d.bit_count()
                flip_bits += h
                if h > 1:
                    multi_bit_bytes += 1
                run += 1
                max_run = max(max_run, run)
            else:
                run = 0
        if flip_bits > BITROT_BIT_CAP:
            break
    rate = diff_bytes / n if n else 0.0
    multi_frac = (multi_bit_bytes / diff_bytes) if diff_bytes else 0.0
    return {
        "diff_bytes": diff_bytes,
        "flip_bits": flip_bits,
        "multi_bit_bytes": multi_bit_bytes,
        "max_run": max_run,
        "rate": rate,
        "is_bitrot": (diff_bytes > 0 and rate < 0.01
                      and multi_frac <= 0.05 and max_run <= 8),
        "capped": flip_bits > BITROT_BIT_CAP,
    }


def bitrot_diff_positions(volume: bytes, reference: bytes) -> List[int]:
    """Byte positions where image and reference differ (chunked int-XOR)."""
    n = min(len(volume), len(reference))
    pos: List[int] = []
    for base in range(0, n, BITROT_MAX_CHUNK):
        chunk_v = volume[base:base + BITROT_MAX_CHUNK]
        # reference may be longer than the volume: slice per-chunk
        chunk_r = reference[base:base + len(chunk_v)]
        xi = int.from_bytes(chunk_v, "little") ^ int.from_bytes(chunk_r,
                                                                "little")
        if xi == 0:
            continue
        cb = xi.to_bytes(len(chunk_v), "little")
        pos.extend(base + i for i, d in enumerate(cb) if d)
    return pos


def repair_bitrot(image: bytearray, reference: bytes) -> Tuple[int, int]:
    """Correct single-bit-flip bytes against the reference. Returns
    (repaired, skipped_multi_bit). Multi-bit bytes are NOT touched."""
    positions = bitrot_diff_positions(bytes(image), reference)
    repaired = skipped = 0
    for i in positions:
        if hamming(image[i], reference[i]) == 1:
            image[i] = reference[i]
            repaired += 1
        else:
            skipped += 1
    return repaired, skipped


# ---------------------------------------------------------------------------
# SQANOM-2: reference-free structural checks (superblock-driven)
# ---------------------------------------------------------------------------
def structural_findings(data: bytes) -> List[str]:
    """Objectively-true integrity findings, analyzer-style wording."""
    out: List[str] = []
    if len(data) < 96 or data[:4] != SQFS_MAGIC_BYTES:
        return out  # not our parse target; --analyze handles that report
    import struct
    (s_magic, inodes, _mkfs_time, block_size, _fragments, _comp, _blog,
     _flags, _no_ids, s_major, s_minor, _root, bytes_used, _idt,
     _xattr, inode_table_start, directory_table_start,
     fragment_table_start, lookup_table_start) = \
        struct.unpack_from("<IIIIIHHHHHHQQQQQQQQ", data, 0)
    size = len(data)
    if bytes_used > size:
        out.append(
            f"TRUNCATED: superblock bytes_used ({bytes_used:,}) exceeds "
            f"file size ({size:,}) -- image is cut short or the dump "
            f"contains trailing garbage")
    for name, off in (("inode_table", inode_table_start),
                      ("directory_table", directory_table_start),
                      ("fragment_table", fragment_table_start),
                      ("lookup_table", lookup_table_start)):
        if off and off >= size:
            out.append(
                f"BAD TABLE OFFSET: {name}_start ({off:,}) lies beyond "
                f"the image ({size:,} B)")
    if inode_table_start and directory_table_start \
            and directory_table_start < inode_table_start:
        out.append(
            "TABLE ORDER: directory_table_start precedes inode_table_start "
            "(valid images always have inode_table first)")
    if inodes == 0:
        out.append("ZERO INODES: superblock claims an empty filesystem")
    if s_major != 4:
        out.append(f"UNSUPPORTED VERSION: SquashFS {s_major}.{s_minor} "
                   f"(this tool targets 4.x)")
    # metadata-block sanity: walk the inode table's u16 block headers while
    # they stay in-bounds; count how many compressed ones start with a
    # known magic (xz/gz/lzma) -- a shifted layout shows up as garbage here
    if inode_table_start and inode_table_start < size and inodes:
        pos = inode_table_start
        blocks = 0
        magic_hits = 0
        while pos + 2 <= size and blocks < 256:
            (h,) = struct.unpack_from("<H", data, pos)
            ln = h & 0x7FFF
            if ln <= 0 or pos + 2 + ln > size:
                break
            blk = data[pos + 2:pos + 2 + ln]
            if not (h & 0x8000):
                if blk[:2] == XZ_MAGIC[:2] or blk[:2] == GZ_MAGIC or \
                        blk[:1] == LZMA_MAGIC[:1]:
                    magic_hits += 1
            blocks += 1
            pos += 2 + ln
        if blocks and magic_hits == 0 and blocks >= 4:
            out.append(
                "METADATA MAGIC: none of the first "
                f"{blocks} inode-table blocks carry a recognizable "
                "compression magic under the declared codec -- the image "
                "may be ECC-shifted or byte-swapped")
    return out


# ---------------------------------------------------------------------------
# CLI-level scan used by sqpack --analyze
# ---------------------------------------------------------------------------
def scan_image(data: bytes, reference: Optional[bytes] = None,
               auto_yes: bool = False, dry_run: bool = False
               ) -> Tuple[List[str], Optional[bytes]]:
    """Run all checks. Returns (findings, repaired_bytes_or_None).

    With a reference: SQANOM-1 classification; bit rot is repaired only
    when auto_yes is set (dry_run reports without touching anything) and
    the repaired image returned. Non-bitrot differences are fatal
    findings. Without a reference: SQANOM-2 only. Never raises; returns
    findings for the report."""
    findings: List[str] = list(structural_findings(data))
    repaired: Optional[bytes] = None
    if reference is not None:
        sig = bitrot_signature(data, reference)
        if sig["diff_bytes"] == 0:
            findings.append("REFERENCE MATCH: image is byte-identical to "
                            "the reference")
        elif sig["is_bitrot"]:
            findings.append(
                f"BIT ROT [repairable]: {sig['diff_bytes']:,} differing "
                f"bytes ({sig['rate'] * 100:.4f}%), "
                f"flip_bits={sig['flip_bits']:,}, "
                f"multi_bit={sig['multi_bit_bytes']}, "
                f"max_run={sig['max_run']}")
            if auto_yes and not dry_run:
                buf = bytearray(data)
                rep, multi = repair_bitrot(buf, reference)
                residual = bitrot_signature(bytes(buf), reference)
                findings.append(
                    f"BIT ROT [repaired]: {rep:,} single-bit bytes "
                    f"corrected vs reference ({multi} multi-bit left, "
                    f"residual {residual['diff_bytes']})")
                repaired = bytes(buf)
        else:
            findings.append(
                f"LAYOUT/CONTENT DIFF vs reference [fatal]: "
                f"{sig['diff_bytes']:,} bytes differ "
                f"(rate {sig['rate'] * 100:.4f}%, max run "
                f"{sig['max_run']}, multi-bit "
                f"{sig['multi_bit_bytes']}) -- not bit rot; do NOT "
                f"auto-repair. Check extraction/reassembly ordering.")
    return findings, repaired
