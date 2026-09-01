"""
tables.py
=========
Parses the fragment table and the id (uid/gid) table. Both share the
same on-disk pattern: the superblock field (`fragment_table_start` /
`id_table_start`) does NOT point directly at a metadata block -- it
points at an "index": a flat, UNCOMPRESSED array of 8-byte
little-endian absolute file offsets, one per metadata block needed to
hold every entry (each metadata block holds at most 8192 bytes of
entries). The actual entries live in the metadata block(s) those
pointers reference.

(This is the same pattern the export/lookup table and xattr id table
use; export table parsing is included for completeness even though it
is not required for the tree walk.)
"""

from __future__ import annotations

import math
import struct
from typing import List, Tuple

from . import inode_structs as S
from .metadata_reader import MetadataReader


def _read_index_pointers(data: bytes, index_start: int, num_blocks: int) -> List[int]:
    ptrs = []
    for i in range(num_blocks):
        off = index_start + i * 8
        (ptr,) = struct.unpack("<Q", data[off:off + 8])
        ptrs.append(ptr)
    return ptrs


def parse_fragment_table(data: bytes, reader: MetadataReader,
                          fragment_table_start: int, num_fragments: int) -> List[Tuple[int, int, bool]]:
    """Returns a list of (start_offset, on_disk_size, is_uncompressed) per
    fragment, in fragment-index order."""
    if num_fragments == 0:
        return []
    entries_per_block = 8192 // S.FRAGMENT_ENTRY.size
    num_blocks = math.ceil(num_fragments / entries_per_block)
    ptrs = _read_index_pointers(data, fragment_table_start, num_blocks)

    out = []
    for ptr in ptrs:
        raw, _, _ = reader.read(ptr, 0, min(8192, S.FRAGMENT_ENTRY.size * num_fragments - len(out) * S.FRAGMENT_ENTRY.size))
        n_here = len(raw) // S.FRAGMENT_ENTRY.size
        for i in range(n_here):
            start, size, _unused = S.FRAGMENT_ENTRY.unpack_from(raw, i * S.FRAGMENT_ENTRY.size)
            is_uncompressed = bool(size & S.SQUASHFS_COMPRESSED_BIT_BLOCK)
            real_size = size & (S.SQUASHFS_COMPRESSED_BIT_BLOCK - 1)
            out.append((start, real_size, is_uncompressed))
    return out[:num_fragments]


def parse_id_table(data: bytes, reader: MetadataReader,
                    id_table_start: int, no_ids: int) -> List[int]:
    """Returns the raw uid/gid VALUES in id-table-index order; inodes
    reference these by index (uid_idx/gid_idx), not by raw value."""
    if no_ids == 0:
        return []
    entries_per_block = 8192 // 4
    num_blocks = math.ceil(no_ids / entries_per_block)
    ptrs = _read_index_pointers(data, id_table_start, num_blocks)

    out = []
    for ptr in ptrs:
        want = min(8192, 4 * no_ids - len(out) * 4)
        raw, _, _ = reader.read(ptr, 0, want)
        n_here = len(raw) // 4
        for i in range(n_here):
            (val,) = struct.unpack_from("<I", raw, i * 4)
            out.append(val)
    return out[:no_ids]
