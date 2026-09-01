"""
directory_parser.py
=====================
Given a directory inode's (start_block, offset, file_size) -- where
start_block is relative to directory_table_start -- reads the directory
table entries: a sequence of (header, then header.count+1 entries)
groups, until `file_size - 3` bytes have been consumed (the "-3" is a
long-standing SquashFS convention: the stored file_size is always 3
bytes larger than the actual listing, historically to account for "."
and ".." that squashfs does NOT actually store as real entries).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from . import inode_structs as S
from .metadata_reader import MetadataReader


@dataclass
class DirEntry:
    name: bytes
    inode_number: int
    inode_block: int   # absolute file offset into the inode table
    inode_offset: int
    type: int          # SQUASHFS inode type (basic types only, 1-7; dirs referenced from a listing are always "type" 1 or the extended equivalent resolved by the inode itself)


def parse_directory(reader: MetadataReader, inode_table_start: int,
                     start_block: int, offset: int, file_size: int) -> List[DirEntry]:
    entries: List[DirEntry] = []
    if file_size <= 3:
        return entries  # empty directory
    remaining = file_size - 3
    cb, co = start_block, offset
    while remaining > 0:
        raw, cb, co = reader.read(cb, co, S.DIR_HEADER.size)
        count, hdr_start_block, hdr_inode_number = S.DIR_HEADER.unpack(raw)
        remaining -= S.DIR_HEADER.size
        for _ in range(count + 1):
            fixed, cb, co = reader.read(cb, co, S.DIR_ENTRY_FIXED.size)
            ent_offset, inode_delta, ent_type, name_size = S.DIR_ENTRY_FIXED.unpack(fixed)
            remaining -= S.DIR_ENTRY_FIXED.size
            name, cb, co = reader.read(cb, co, name_size + 1)
            remaining -= (name_size + 1)
            entries.append(DirEntry(
                name=name,
                inode_number=hdr_inode_number + inode_delta,
                inode_block=inode_table_start + hdr_start_block,
                inode_offset=ent_offset,
                type=ent_type,
            ))
    return entries
