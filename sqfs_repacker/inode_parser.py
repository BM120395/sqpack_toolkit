"""
inode_parser.py
================
Parses one inode (any of the 14 SquashFS 4.x inode types) starting at a
given (block_start, offset) location in the inode table, using a
MetadataReader for the actual bytes. Returns a single, type-agnostic
`Inode` dataclass -- callers branch on `.kind` rather than needing to
know which raw struct was used, but every field that exists on disk is
preserved (nothing is thrown away).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import inode_structs as S
from .metadata_reader import MetadataReader


@dataclass
class Inode:
    kind: str                  # "dir" | "file" | "symlink" | "chrdev" | "blkdev" | "fifo" | "socket"
    extended: bool
    mode: int
    uid_idx: int
    gid_idx: int
    mtime: int
    inode_number: int
    nlink: int = 1
    xattr_idx: int = S.SQUASHFS_INVALID_XATTR

    # dir
    dir_start_block: Optional[int] = None   # relative to directory_table_start
    dir_offset: Optional[int] = None
    dir_file_size: Optional[int] = None
    dir_parent_inode: Optional[int] = None

    # file
    file_start_block: Optional[int] = None  # absolute file offset of first data block
    file_size: Optional[int] = None
    fragment_index: int = S.SQUASHFS_INVALID_FRAG
    fragment_offset: int = 0
    block_sizes: List[int] = field(default_factory=list)   # raw 32-bit entries (compressed-flag bit included)

    # symlink
    symlink_target: Optional[bytes] = None

    # device
    rdev: Optional[int] = None

    # -- Phase 3 repack-time extensions (unused by Phase 2 parsing) --
    # When set, this node's file content should be freshly compressed
    # from these bytes rather than reused verbatim from the original
    # image's block_sizes/file_start_block/fragment_index. Used by
    # both --patch (content replace) and --source-dir (modified/added
    # files) -- the same field, the same downstream code path, per the
    # "one shared build() pipeline" requirement.
    raw_content: Optional[bytes] = None
    # Original on-image file size, captured before raw_content/file_size
    # are replaced with new content (repack-time only). Pass B needs it to
    # know the file's OLD tail footprint inside a carried fragment --
    # after a MODIFIED merge, file_size already reflects the NEW content.
    orig_file_size: Optional[int] = None
    # When set, this node's ownership differs from the original and the
    # RAW uid/gid value (not yet resolved to an id-table index) is
    # pending resolution once the final id table is known. None means
    # "use uid_idx/gid_idx as already set" (unchanged from the original).
    pending_uid: Optional[int] = None
    pending_gid: Optional[int] = None

    def to_manifest_dict(self) -> dict:
        d = {
            "kind": self.kind,
            "extended": self.extended,
            "mode": oct(self.mode),
            "uid_idx": self.uid_idx,
            "gid_idx": self.gid_idx,
            "mtime": self.mtime,
            "inode_number": self.inode_number,
            "nlink": self.nlink,
        }
        if self.xattr_idx != S.SQUASHFS_INVALID_XATTR:
            d["xattr_idx"] = self.xattr_idx
        if self.kind == "dir":
            d.update(dir_start_block=self.dir_start_block, dir_offset=self.dir_offset,
                      dir_file_size=self.dir_file_size, dir_parent_inode=self.dir_parent_inode)
        elif self.kind == "file":
            d.update(file_size=self.file_size,
                      fragment_index=None if self.fragment_index == S.SQUASHFS_INVALID_FRAG else self.fragment_index,
                      fragment_offset=self.fragment_offset if self.fragment_index != S.SQUASHFS_INVALID_FRAG else None,
                      num_blocks=len(self.block_sizes))
        elif self.kind == "symlink":
            d["symlink_target"] = self.symlink_target.decode("utf-8", "surrogateescape")
        elif self.kind in ("chrdev", "blkdev"):
            d.update(rdev=self.rdev, major=self.rdev >> 8, minor=self.rdev & 0xff)
        return d


def parse_inode(reader: MetadataReader, block_start: int, offset: int) -> Inode:
    raw, cb, co = reader.read(block_start, offset, S.BASE_INODE.size)
    itype, mode, uid_idx, gid_idx, mtime, inode_number = S.BASE_INODE.unpack(raw)

    if itype == S.INODE_TYPE_BASIC_DIR:
        raw2, cb, co = reader.read(cb, co, S.DIR_EXTRA.size)
        start_block, nlink, file_size, dir_offset, parent_inode = S.DIR_EXTRA.unpack(raw2)
        return Inode("dir", False, mode, uid_idx, gid_idx, mtime, inode_number, nlink,
                      dir_start_block=start_block, dir_offset=dir_offset,
                      dir_file_size=file_size, dir_parent_inode=parent_inode)

    if itype == S.INODE_TYPE_EXT_DIR:
        raw2, cb, co = reader.read(cb, co, S.LDIR_EXTRA_FIXED.size)
        nlink, file_size, start_block, parent_inode, i_count, dir_offset = S.LDIR_EXTRA_FIXED.unpack(raw2)
        raw3, cb, co = reader.read(cb, co, 4)
        (xattr_idx,) = struct_unpack_u32(raw3)
        # Skip the i_count+1 squashfs_dir_index entries (readdir optimization
        # index -- not needed to walk the tree, but we must consume the
        # correct number of bytes to leave the reader positioned after this
        # inode for whoever parses the next one).
        #
        # CORRECT format of each dir_index entry (fs/squashfs/squashfs_fs.h):
        #   struct squashfs_dir_index {
        #       __le32 index;          // offset into the dir listing
        #       __le32 start_block;    // metadata block where that index lands
        #       __le32 size;           // size of the directory listing (NOT name length!)
        #       char    name[];        // null-terminated, variable length
        #   };
        # The name field has NO length prefix -- it is null-terminated. The
        # previous version of this code mistakenly read `size` as name_size
        # and tried to skip `size+1` bytes, which chain-walked across many
        # metadata blocks and crashed on the first block whose first byte
        # was not the XZ magic (typically the fragment table boundary).
        # The fix is to scan forward for the null terminator byte-by-byte,
        # chaining metadata blocks if needed, until we find it.
        for _ in range(i_count + 1):
            hdr, cb, co = reader.read(cb, co, 12)  # index(u32), start_block(u32), size(u32)
            # Scan for null terminator of the name. The name may cross
            # metadata block boundaries (rare for short index names, but
            # legal by the format), so do this one byte at a time using
            # reader.read() rather than reading a fixed-size chunk.
            while True:
                name_chunk, cb, co = reader.read(cb, co, 1)
                if name_chunk == b"\x00":
                    break
        return Inode("dir", True, mode, uid_idx, gid_idx, mtime, inode_number, nlink,
                      xattr_idx=xattr_idx, dir_start_block=start_block, dir_offset=dir_offset,
                      dir_file_size=file_size, dir_parent_inode=parent_inode)

    if itype == S.INODE_TYPE_BASIC_FILE:
        raw2, cb, co = reader.read(cb, co, S.REG_EXTRA.size)
        start_block, fragment, frag_offset, file_size = S.REG_EXTRA.unpack(raw2)
        n_blocks = _num_full_blocks(file_size, fragment)
        block_sizes, cb, co = _read_block_list(reader, cb, co, n_blocks)
        return Inode("file", False, mode, uid_idx, gid_idx, mtime, inode_number, 1,
                      file_start_block=start_block, file_size=file_size,
                      fragment_index=fragment, fragment_offset=frag_offset,
                      block_sizes=block_sizes)

    if itype == S.INODE_TYPE_EXT_FILE:
        raw2, cb, co = reader.read(cb, co, S.LREG_EXTRA.size)
        start_block, file_size, sparse, nlink, fragment, frag_offset, xattr_idx = S.LREG_EXTRA.unpack(raw2)
        n_blocks = _num_full_blocks(file_size, fragment)
        block_sizes, cb, co = _read_block_list(reader, cb, co, n_blocks)
        return Inode("file", True, mode, uid_idx, gid_idx, mtime, inode_number, nlink,
                      xattr_idx=xattr_idx, file_start_block=start_block, file_size=file_size,
                      fragment_index=fragment, fragment_offset=frag_offset,
                      block_sizes=block_sizes)

    if itype in (S.INODE_TYPE_BASIC_SYMLINK, S.INODE_TYPE_EXT_SYMLINK):
        raw2, cb, co = reader.read(cb, co, S.SYMLINK_EXTRA.size)
        nlink, sym_size = S.SYMLINK_EXTRA.unpack(raw2)
        target, cb, co = reader.read(cb, co, sym_size)
        xattr_idx = S.SQUASHFS_INVALID_XATTR
        extended = itype == S.INODE_TYPE_EXT_SYMLINK
        if extended:
            raw3, cb, co = reader.read(cb, co, 4)
            (xattr_idx,) = struct_unpack_u32(raw3)
        return Inode("symlink", extended, mode, uid_idx, gid_idx, mtime, inode_number, nlink,
                      xattr_idx=xattr_idx, symlink_target=target)

    if itype in (S.INODE_TYPE_BASIC_BLKDEV, S.INODE_TYPE_BASIC_CHRDEV):
        raw2, cb, co = reader.read(cb, co, S.DEV_EXTRA.size)
        nlink, rdev = S.DEV_EXTRA.unpack(raw2)
        kind = "blkdev" if itype == S.INODE_TYPE_BASIC_BLKDEV else "chrdev"
        return Inode(kind, False, mode, uid_idx, gid_idx, mtime, inode_number, nlink, rdev=rdev)

    if itype in (S.INODE_TYPE_EXT_BLKDEV, S.INODE_TYPE_EXT_CHRDEV):
        raw2, cb, co = reader.read(cb, co, S.LDEV_EXTRA.size)
        nlink, rdev, xattr_idx = S.LDEV_EXTRA.unpack(raw2)
        kind = "blkdev" if itype == S.INODE_TYPE_EXT_BLKDEV else "chrdev"
        return Inode(kind, True, mode, uid_idx, gid_idx, mtime, inode_number, nlink,
                      xattr_idx=xattr_idx, rdev=rdev)

    if itype in (S.INODE_TYPE_BASIC_FIFO, S.INODE_TYPE_BASIC_SOCKET):
        raw2, cb, co = reader.read(cb, co, S.IPC_EXTRA.size)
        (nlink,) = S.IPC_EXTRA.unpack(raw2)
        kind = "fifo" if itype == S.INODE_TYPE_BASIC_FIFO else "socket"
        return Inode(kind, False, mode, uid_idx, gid_idx, mtime, inode_number, nlink)

    if itype in (S.INODE_TYPE_EXT_FIFO, S.INODE_TYPE_EXT_SOCKET):
        raw2, cb, co = reader.read(cb, co, S.LIPC_EXTRA.size)
        nlink, xattr_idx = S.LIPC_EXTRA.unpack(raw2)
        kind = "fifo" if itype == S.INODE_TYPE_EXT_FIFO else "socket"
        return Inode(kind, True, mode, uid_idx, gid_idx, mtime, inode_number, nlink, xattr_idx=xattr_idx)

    raise ValueError(f"Unknown inode type {itype} at block_start={block_start} offset={offset}")


def _num_full_blocks(file_size: int, fragment: int) -> int:
    """How many full-block block_list[] entries a regular file inode has.
    If it has no fragment (fragment == INVALID_FRAG), even a partial final
    block is stored as a full block-list entry; otherwise the trailing
    partial block is carved off into a fragment and NOT counted here."""
    import math
    if fragment == S.SQUASHFS_INVALID_FRAG:
        return (file_size + _BLOCK_SIZE_HINT[0] - 1) // _BLOCK_SIZE_HINT[0] if _BLOCK_SIZE_HINT[0] else 0
    return file_size // _BLOCK_SIZE_HINT[0] if _BLOCK_SIZE_HINT[0] else 0


# Set once, by tree.py, from the superblock's block_size before any parsing
# starts -- kept as a tiny module-level hint rather than threading block_size
# through every call, since it is a single filesystem-wide constant.
_BLOCK_SIZE_HINT = [None]


def set_block_size_hint(block_size: int) -> None:
    _BLOCK_SIZE_HINT[0] = block_size


def _read_block_list(reader: MetadataReader, block_start: int, offset: int, n: int):
    if n == 0:
        return [], block_start, offset
    raw, cb, co = reader.read(block_start, offset, n * S.BLOCK_SIZE_ENTRY.size)
    sizes = [raw[i * 4:(i + 1) * 4] for i in range(n)]
    sizes = [struct_unpack_u32(b)[0] for b in sizes]
    return sizes, cb, co


def struct_unpack_u32(b: bytes):
    import struct
    return struct.unpack("<I", b)
