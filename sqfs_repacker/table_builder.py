"""
table_builder.py
=================
Shared machinery for building the inode table and directory table.

The hard problem these two tables have is a MUTUAL reference: a
directory's on-disk listing (in the directory table) contains pointers
to its children's inode positions (in the inode table); a directory's
OWN inode record (in the inode table) contains a pointer to where its
listing lives (in the directory table). Each table's final compressed
byte layout depends on the other table's final compressed byte layout
-- a genuine mutual dependency, not just an ordering inconvenience.

We solve it the same way you'd solve any small fixed-point problem:
build both tables with zeroed placeholder fields wherever a
cross-table position is needed, compress both, then repeatedly (a) fill
in the placeholders using the other table's current resolver and (b)
recompress, until neither table's compressed bytes change between
rounds. This converges essentially always in 2 rounds in practice --
patched fields are a handful of bytes inside an 8192-byte block, so a
placeholder-vs-real difference changes a chunk's compressed size by at
most a few bytes, which almost never cascades. We iterate up to a
bounded number of rounds and raise loudly rather than silently emitting
a wrong pointer if it somehow doesn't settle.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from . import constants as C
from .encoder import encode_metadata_block
from .compressor import CompressorProfile


@dataclass
class Patch:
    byte_offset: int          # offset within this table's raw buffer
    fmt: str                  # struct format for the field(s) to write
    ref_raw_offset: int       # raw offset INTO THE OTHER TABLE that this field must resolve to
    part: str = "both"        # "both" (block_rel+in_block via fmt like "<IH"),
                               # "block" (block_rel only, e.g. fmt="<I"),
                               # "offset" (in_block only, e.g. fmt="<H")


class MetadataTableBuilder:
    """Accumulates one table's logical (uncompressed) byte content, plus a
    list of deferred cross-table patches to apply once the other table's
    layout is known."""

    def __init__(self):
        self.buf = bytearray()
        self.patches: List[Patch] = []

    def write(self, data: bytes) -> int:
        """Append bytes, return the RAW offset where this write started --
        this is a stable identity other code can reference immediately,
        even though the final compressed (block, offset) pair isn't known
        until the whole table is finalized."""
        off = len(self.buf)
        self.buf += data
        return off

    def reserve_patch(self, nbytes: int, fmt: str, ref_raw_offset: int) -> None:
        """Write `nbytes` of zero placeholder at the current position and
        remember to patch it in later once `ref_raw_offset` (a position in
        the OTHER table) has a resolved (block, offset)."""
        off = len(self.buf)
        self.buf += b"\x00" * nbytes
        self.patches.append(Patch(off, fmt, ref_raw_offset))

    def apply_patches(self, other_resolve: Callable[[int], Tuple[int, int]]) -> None:
        for p in self.patches:
            block_rel, in_block = other_resolve(p.ref_raw_offset)
            if p.part == "both":
                packed = struct.pack(p.fmt, block_rel, in_block)
            elif p.part == "block":
                packed = struct.pack(p.fmt, block_rel)
            elif p.part == "offset":
                packed = struct.pack(p.fmt, in_block)
            else:
                raise ValueError(f"unknown patch part {p.part!r}")
            self.buf[p.byte_offset: p.byte_offset + len(packed)] = packed

    def chunk_raw(self) -> List[bytes]:
        raw = bytes(self.buf)
        if not raw:
            return [b""]
        return [raw[i:i + C.METADATA_MAX_SIZE] for i in range(0, len(raw), C.METADATA_MAX_SIZE)]


def compress_table(builder: MetadataTableBuilder, comp_id: int,
                    profile: CompressorProfile) -> Tuple[bytes, Callable[[int], Tuple[int, int]], List[int]]:
    """Compress every 8192-byte raw chunk of `builder` in order, returning:
      - the concatenated on-disk table bytes (each chunk's 2-byte header + payload)
      - a resolve(raw_offset) -> (block_rel_to_table_start, offset_within_block) function
      - the list of each chunk's compressed byte length (for convergence comparison)
    """
    chunks = builder.chunk_raw()
    out = bytearray()
    chunk_starts = []   # compressed-relative start offset of each chunk
    chunk_lengths = []
    for chunk in chunks:
        chunk_starts.append(len(out))
        block_bytes = encode_metadata_block(chunk, comp_id, profile)
        out += block_bytes
        chunk_lengths.append(len(block_bytes))

    def resolve(raw_offset: int) -> Tuple[int, int]:
        idx = raw_offset // C.METADATA_MAX_SIZE
        in_block = raw_offset % C.METADATA_MAX_SIZE
        if idx >= len(chunk_starts):
            # raw_offset points exactly at the end of the last chunk (e.g.
            # an empty trailing table) -- treat as start of a (virtual) new
            # empty chunk at the current end.
            return len(out), 0
        return chunk_starts[idx], in_block

    return bytes(out), resolve, chunk_lengths


def build_mutual_tables(inode_builder: MetadataTableBuilder, dir_builder: MetadataTableBuilder,
                         comp_id: int, profile: CompressorProfile,
                         max_rounds: int = 8) -> Tuple[bytes, bytes,
                                                        Callable[[int], Tuple[int, int]],
                                                        Callable[[int], Tuple[int, int]]]:
    """Runs the fixed-point convergence described above. Returns the final
    (inode_table_bytes, directory_table_bytes, resolve_inode, resolve_dir)."""
    # Round 0: compress with placeholders still zero, just to get a first resolver.
    inode_bytes, resolve_inode, inode_lengths = compress_table(inode_builder, comp_id, profile)
    dir_bytes, resolve_dir, dir_lengths = compress_table(dir_builder, comp_id, profile)

    for round_no in range(max_rounds):
        inode_builder.apply_patches(resolve_dir)
        dir_builder.apply_patches(resolve_inode)

        new_inode_bytes, new_resolve_inode, new_inode_lengths = compress_table(inode_builder, comp_id, profile)
        new_dir_bytes, new_resolve_dir, new_dir_lengths = compress_table(dir_builder, comp_id, profile)

        stable = (new_inode_lengths == inode_lengths) and (new_dir_lengths == dir_lengths)
        inode_bytes, resolve_inode, inode_lengths = new_inode_bytes, new_resolve_inode, new_inode_lengths
        dir_bytes, resolve_dir, dir_lengths = new_dir_bytes, new_resolve_dir, new_dir_lengths

        if stable:
            return inode_bytes, dir_bytes, resolve_inode, resolve_dir

    raise RuntimeError(
        f"inode/directory table mutual-reference resolution did not converge "
        f"after {max_rounds} rounds -- this would indicate an unusually large "
        f"filesystem where cross-table patches keep shifting chunk boundaries; "
        f"please report this rather than trusting the (potentially wrong) output."
    )
