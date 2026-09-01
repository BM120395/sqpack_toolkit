"""
tree.py
=======
Phase 2 orchestrator. Given a parsed superblock and the raw file bytes:
  1. builds the compressor profile (auto-detected on the first block),
  2. parses the id table and fragment table,
  3. walks the directory tree from root_inode, parsing every inode along
     the way into a full in-memory `FSNode` tree with every recoverable
     attribute,
  4. can materialize real file content for any regular file by resolving
     its data blocks + optional trailing fragment.

This is intentionally compressor- and vendor-agnostic: everything that
is specific to how THIS image's LZMA blocks are framed lives in
compressor.py's auto-detection, not here. Point this at a differently
built SquashFS image (different compressor, different LZMA framing, or
no vendor quirks at all -- i.e. a normal mksquashfs image) and this
module does not need to change.
"""

from __future__ import annotations

import os
import stat as statmod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .superblock import Superblock
from .compressor import CompressorProfile, decompress_block, DecodeError
from .metadata_reader import MetadataReader
from .inode_parser import Inode, parse_inode, set_block_size_hint
from .directory_parser import parse_directory, DirEntry
from .tables import parse_fragment_table, parse_id_table
from . import inode_structs as S


@dataclass
class FSNode:
    name: str
    path: str
    inode: Inode
    children: List["FSNode"] = field(default_factory=list)

    def to_manifest_dict(self) -> dict:
        d = {"name": self.name, "path": self.path, **self.inode.to_manifest_dict()}
        if self.children:
            d["children"] = [c.to_manifest_dict() for c in self.children]
        return d


class FilesystemImage:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.data = f.read()
        from .superblock import parse_superblock
        self.sb: Superblock = parse_superblock(self.data)
        self.sb.file_size_on_disk = len(self.data)

        set_block_size_hint(self.sb.block_size)

        self.profile = CompressorProfile(self.sb.compression)

        # Read compressor options block (if present) for XZ/LZMA decompression.
        # For XZ (comp_id=4), the first 4 bytes at offset 96 encode dict_size.
        # The full block is 14 bytes at superblock offset 96.
        if self.sb.has_compressor_options and self.sb.compression == 4:
            self.xz_options_block = self.data[96:110]
        else:
            self.xz_options_block = None

        self.reader = MetadataReader(self.data, self.sb.compression, self.profile,
                                     xz_options_block=self.xz_options_block)

        self.id_table = parse_id_table(
            self.data, self.reader, self.sb.id_table_start, self.sb.no_ids
        ) if self.sb.id_table_start != 0xFFFFFFFFFFFFFFFF else []

        self.fragment_table = parse_fragment_table(
            self.data, self.reader, self.sb.fragment_table_start, self.sb.fragments
        ) if (self.sb.fragment_table_start != 0xFFFFFFFFFFFFFFFF and self.sb.fragments > 0) else []

        # After id/fragment table parsing, self.reader.profile has been
        # refined by whatever auto-detection succeeded -- keep it as the
        # canonical profile for everything else (inode/dir/data blocks).
        self.profile = self.reader.profile

        self.root: Optional[FSNode] = None
        self.inode_by_number: Dict[int, FSNode] = {}

    # -- tree walking ------------------------------------------------
    def build_tree(self) -> FSNode:
        root_ref = self.sb.root_inode
        block = self.sb.inode_table_start + (root_ref >> 16)
        offset = root_ref & 0xFFFF
        root_inode = parse_inode(self.reader, block, offset)
        self.root = FSNode("", "/", root_inode)
        self.inode_by_number[root_inode.inode_number] = self.root
        self._walk(self.root)
        return self.root

    def _walk(self, node: FSNode):
        if node.inode.kind != "dir":
            return
        abs_start = self.sb.directory_table_start + node.inode.dir_start_block
        entries = parse_directory(
            self.reader, self.sb.inode_table_start,
            abs_start, node.inode.dir_offset, node.inode.dir_file_size
        )
        for ent in entries:
            child_inode = parse_inode(self.reader, ent.inode_block, ent.inode_offset)
            child_path = (node.path.rstrip("/") + "/" + ent.name.decode("utf-8", "surrogateescape"))
            child = FSNode(ent.name.decode("utf-8", "surrogateescape"), child_path, child_inode)
            node.children.append(child)
            self.inode_by_number[child_inode.inode_number] = child
            if child_inode.kind == "dir":
                self._walk(child)

    # -- file content extraction --------------------------------------
    def read_file_content(self, inode: Inode) -> bytes:
        assert inode.kind == "file"
        out = bytearray()
        pos = self.sb.inode_table_start  # unused; kept for clarity
        cur_offset = inode.file_start_block
        for raw_entry in inode.block_sizes:
            is_uncompressed = bool(raw_entry & S.SQUASHFS_COMPRESSED_BIT_BLOCK)
            size = raw_entry & (S.SQUASHFS_COMPRESSED_BIT_BLOCK - 1)
            if size == 0:
                # a hole (sparse block) -- squashfs represents an all-zero
                # block with a zero-length entry and writes nothing on disk
                out += b"\x00" * self.sb.block_size
                continue
            chunk = self.data[cur_offset: cur_offset + size]
            if is_uncompressed:
                out += chunk
            else:
                decoded, self.profile = decompress_block(
                    chunk, self.sb.compression, self.profile, max_size=self.sb.block_size,
                    xz_options_block=self.xz_options_block
                )
                out += decoded
            cur_offset += size

        if inode.fragment_index != S.SQUASHFS_INVALID_FRAG:
            frag_start, frag_size, frag_uncompressed = self.fragment_table[inode.fragment_index]
            chunk = self.data[frag_start: frag_start + frag_size]
            if frag_uncompressed:
                frag_data = chunk
            else:
                frag_data, self.profile = decompress_block(
                    chunk, self.sb.compression, self.profile, max_size=self.sb.block_size,
                    xz_options_block=self.xz_options_block
                )
            tail_len = inode.file_size - len(out)
            out += frag_data[inode.fragment_offset: inode.fragment_offset + tail_len]

        return bytes(out[: inode.file_size])

    def resolve_uid_gid(self, inode: Inode):
        def _val(idx):
            if 0 <= idx < len(self.id_table):
                return self.id_table[idx]
            return None
        return _val(inode.uid_idx), _val(inode.gid_idx)


def iter_nodes(root: FSNode):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def mode_to_str(mode: int, kind: str) -> str:
    type_bits = {
        "dir": statmod.S_IFDIR, "file": statmod.S_IFREG, "symlink": statmod.S_IFLNK,
        "chrdev": statmod.S_IFCHR, "blkdev": statmod.S_IFBLK,
        "fifo": statmod.S_IFIFO, "socket": statmod.S_IFSOCK,
    }.get(kind, 0)
    try:
        return statmod.filemode(type_bits | (mode & 0o7777))
    except Exception:
        return "?" * 10
