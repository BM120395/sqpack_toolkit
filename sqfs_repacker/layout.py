"""
layout.py
=========
Builds a byte-exact map of every region in the SquashFS image purely from
the offsets already published in the superblock -- no decompression
needed. This is deliberately robust: SquashFS does not guarantee tables
appear on disk in any particular order (reference tool versions differ), so
we discover the layout by sorting whichever start offsets are actually
present, rather than assuming a fixed order.

The resulting `Region` list is the backbone of both the human-readable
forensic log and the JSON report: every byte of the file is accounted
for and attributed to something (a table, the data area, or padding).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional

from . import constants as C
from .superblock import Superblock


@dataclass
class Region:
    name: str
    start: int
    end: int  # exclusive
    sha256: str = ""

    @property
    def size(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "size": self.size,
            "sha256": self.sha256,
        }


def _hash(data: bytes, start: int, end: int) -> str:
    return hashlib.sha256(data[start:end]).hexdigest()


def build_layout(sb: Superblock, data: bytes) -> List[Region]:
    """Compute contiguous, non-overlapping regions covering [0, len(data)).

    Strategy: gather every *present* table start offset from the
    superblock, plus the fixed points we know for certain (offset 0 for
    the superblock, and bytes_used for the end of meaningful content).
    Sort them, and each named table's region runs from its own start to
    the next-higher start offset in the sorted list (or bytes_used for
    whichever table is last). Anything between bytes_used and the actual
    file length is reported separately as trailing/padding data.
    """
    file_len = len(data)
    invalid = C.SQUASHFS_INVALID_BLK

    # offset -> label, for every table that is actually present
    markers = {0: "superblock"}

    comp_opts_end = C.SUPERBLOCK_SIZE
    if sb.has_compressor_options:
        # Compressor options block is itself one metadata-block-framed
        # blob starting immediately at offset 96. We don't know its exact
        # compressed length without reading the 2-byte metadata header,
        # so peek it here (cheap, doesn't require decompression).
        hdr = int.from_bytes(data[96:98], "little")
        comp_len = hdr & C.METADATA_LENGTH_MASK
        comp_opts_end = 96 + C.METADATA_BLOCK_HEADER_SIZE + comp_len
        markers[96] = "compressor_options"

    # IMPORTANT: unlike the inode/directory/fragment/id/export tables,
    # there is no superblock field marking where the data+fragment block
    # area *starts* -- but we know it always begins immediately after the
    # superblock (and compressor-options block, if present), and runs
    # until whichever table happens to be lowest-addressed on disk.
    # the reference tools' actual on-disk order is data area first, then (at the
    # tail of the file) inode table, directory table, fragment table,
    # export table, id table, xattr table, in a version-dependent order --
    # so we must NOT assume the inode table immediately follows the
    # superblock; inode_table_start is authoritative and usually points
    # much further into the file.
    markers[comp_opts_end] = "data_and_fragment_blocks"
    if sb.inode_table_start not in markers:
        markers[sb.inode_table_start] = "inode_table"

    # directory table start is not in the superblock explicitly as a
    # separate field name other than 'directory_table_start'
    if sb.directory_table_start != invalid:
        markers[sb.directory_table_start] = "directory_table"
    if sb.fragment_table_start != invalid and sb.fragments > 0:
        markers[sb.fragment_table_start] = "fragment_table_index"
    if sb.lookup_table_start != invalid:
        markers[sb.lookup_table_start] = "export_lookup_table"
    if sb.id_table_start != invalid:
        markers[sb.id_table_start] = "id_table_index"
    if sb.xattr_id_table_start != invalid:
        markers[sb.xattr_id_table_start] = "xattr_id_table"

    # sort by offset, build contiguous regions
    sorted_offsets = sorted(markers.items(), key=lambda kv: kv[0])
    regions: List[Region] = []
    for i, (offset, label) in enumerate(sorted_offsets):
        if i + 1 < len(sorted_offsets):
            end = sorted_offsets[i + 1][0]
        else:
            end = sb.bytes_used
        if end < offset:
            # Overlapping/out-of-order tables -- record as a finding rather
            # than crash; this can legitimately happen with some vendor
            # mkfs variants that reorder tables.
            end = offset
        regions.append(Region(label, offset, end, _hash(data, offset, end)))

    # Superblock itself is only 96 bytes; if compressor options pushed
    # inode_table further out we already accounted for that above, but
    # fix up the "superblock" region's own end (it should stop at 96,
    # not run into comp opts).
    for r in regions:
        if r.name == "superblock":
            r.end = min(r.end, C.SUPERBLOCK_SIZE)
            r.sha256 = _hash(data, r.start, r.end)

    if sb.bytes_used < file_len:
        regions.append(
            Region(
                "trailing_data_after_bytes_used",
                sb.bytes_used,
                file_len,
                _hash(data, sb.bytes_used, file_len),
            )
        )

    return regions
