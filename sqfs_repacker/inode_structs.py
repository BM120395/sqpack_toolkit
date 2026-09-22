"""
inode_structs.py
=================
Exact byte layouts of every SquashFS 4.x inode type and directory table
record, transcribed from the authoritative kernel source
(fs/squashfs/squashfs_fs.h) -- not reconstructed from memory of how
squashfs "usually" looks. Field names match the kernel header so this
file can be cross-checked against it directly.

One deliberate deviation: the kernel header declares regular-file block
lists as `__le16 block_list[0]`, which is a long-standing documentation
artifact -- every real implementation (reference SquashFS implementations,
squashfuse, 7-Zip's plugin, etc.) treats block-size entries as 4-byte
(__le32) values, since a block size needs to represent up to
SQUASHFS_FILE_MAX_SIZE with a compressed-flag bit at bit 24 (see
SQUASHFS_COMPRESSED_BIT_BLOCK). We use le32 here and it is verified
against the actual uploaded image in tree.py's self-check.
"""

from __future__ import annotations

import struct

INODE_TYPE_BASIC_DIR = 1
INODE_TYPE_BASIC_FILE = 2
INODE_TYPE_BASIC_SYMLINK = 3
INODE_TYPE_BASIC_BLKDEV = 4
INODE_TYPE_BASIC_CHRDEV = 5
INODE_TYPE_BASIC_FIFO = 6
INODE_TYPE_BASIC_SOCKET = 7
INODE_TYPE_EXT_DIR = 8
INODE_TYPE_EXT_FILE = 9
INODE_TYPE_EXT_SYMLINK = 10
INODE_TYPE_EXT_BLKDEV = 11
INODE_TYPE_EXT_CHRDEV = 12
INODE_TYPE_EXT_FIFO = 13
INODE_TYPE_EXT_SOCKET = 14

SQUASHFS_INVALID_FRAG = 0xFFFFFFFF
SQUASHFS_INVALID_XATTR = 0xFFFFFFFF
SQUASHFS_INVALID_BLK32 = 0xFFFFFFFF

# base header shared by every inode type (16 bytes)
BASE_INODE = struct.Struct("<HHHHII")  # type, mode, uid_idx, gid_idx, mtime, inode_number

# type-specific extra fields (base header already consumed separately)
DIR_EXTRA = struct.Struct("<IIHHI")          # start_block, nlink, file_size(u16), offset(u16), parent_inode
LDIR_EXTRA_FIXED = struct.Struct("<IIIIHH")  # nlink, file_size, start_block, parent_inode, i_count, offset
# ldir xattr (u32) follows LDIR_EXTRA_FIXED, then i_count+1 squashfs_dir_index entries

REG_EXTRA = struct.Struct("<IIII")           # start_block, fragment, offset, file_size
LREG_EXTRA = struct.Struct("<QQQIIII")       # start_block, file_size, sparse, nlink, fragment, offset, xattr

SYMLINK_EXTRA = struct.Struct("<II")         # nlink, symlink_size  (symlink text follows, then xattr(u32) if extended)

DEV_EXTRA = struct.Struct("<II")             # nlink, rdev
LDEV_EXTRA = struct.Struct("<III")           # nlink, rdev, xattr

IPC_EXTRA = struct.Struct("<I")              # nlink
LIPC_EXTRA = struct.Struct("<II")            # nlink, xattr

BLOCK_SIZE_ENTRY = struct.Struct("<I")       # one entry in a regular file's block_list[]
SQUASHFS_COMPRESSED_BIT_BLOCK = 1 << 24

# --- directory table -----------------------------------------------------
DIR_HEADER = struct.Struct("<III")        # count, start_block, inode_number
DIR_ENTRY_FIXED = struct.Struct("<HhHH")  # offset(u16), inode_number_delta(i16), type(u16), size(u16)  (name follows)

# --- fragment table entry -------------------------------------------------
FRAGMENT_ENTRY = struct.Struct("<QII")  # start_block(u64), size(u32, top bit = uncompressed), unused(u32)
