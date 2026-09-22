"""
constants.py
============
Static, format-level constants for the SquashFS 4.0 on-disk layout.

These values come from the published squashfs_fs.h header used by
squashfs-tools / the Linux kernel squashfs driver. They are NOT
heuristics -- they are fixed by the file format specification, so
hard-coding them here is correct and will never need to be "inferred".

Everything that IS variable per-image (block size, compression choice,
flags, table offsets, counts...) lives in the superblock itself and is
parsed at runtime -- see superblock.py.
"""

import struct

# --- Magic / version -------------------------------------------------
SQUASHFS_MAGIC = 0x73717368          # "hsqs" little-endian on disk
SQUASHFS_MAGIC_SWAP = 0x68737173     # big-endian images (rare, old mips fw)
SUPPORTED_MAJOR = 4
SUPPORTED_MINOR = 0

# --- Superblock ---------------------------------------------------------
# 96-byte fixed-size structure, all little-endian for MAGIC (LE) images.
# Field order and widths are exactly as in squashfs_fs.h's
# struct squashfs_super_block.
SUPERBLOCK_SIZE = 96
SUPERBLOCK_STRUCT = struct.Struct("<IIIIIHHHHHHQQQQQQQQ")
SUPERBLOCK_FIELDS = [
    "s_magic",
    "inodes",
    "mkfs_time",
    "block_size",
    "fragments",
    "compression",
    "block_log",
    "flags",
    "no_ids",
    "s_major",
    "s_minor",
    "root_inode",
    "bytes_used",
    "id_table_start",
    "xattr_id_table_start",
    "inode_table_start",
    "directory_table_start",
    "fragment_table_start",
    "lookup_table_start",
]
assert SUPERBLOCK_STRUCT.size == SUPERBLOCK_SIZE

# A field value of this constant means "table not present"
SQUASHFS_INVALID_BLK = 0xFFFFFFFFFFFFFFFF

# --- Compression ids (superblock.compression) ---------------------------
COMPRESSION_IDS = {
    0: "NONE (uncompressed, non-standard)",
    1: "ZLIB",
    2: "LZMA",   # legacy / vendor id -- NOT supported by stock reference tools,
                 # which only writes XZ. Extremely common in router/IoT
                 # firmware built with the old "squashfs-lzma" fork or
                 # OpenWrt's lzma xz-utils shim (quirk-aware readers' target format).
    3: "LZO",
    4: "XZ",
    5: "LZ4",
    6: "ZSTD",
}

# Reverse map for --compression CLI flag. Names match what users expect
# (gzip==zlib on the wire; squashfs-tools uses the reference tool CLI name).
COMPRESSION_NAMES = {
    "gzip":  1,
    "zlib":  1,    # alias for gzip (squashfs's gzip is zlib-wrapped deflate)
    "lzma":  2,
    "xz":    4,
    "lzo":   3,
    "lz4":   5,
    "zstd":  6,
}

# --- Superblock flag bits (bit position, not mask) -----------------------
# Value stored in the superblock is a bitmask; SQUASHFS_*_BIT gives the
# bit index, consistent with squashfs_fs.h's SQUASHFS_BIT() macros.
FLAG_BITS = {
    "UNCOMPRESSED_INODES": 0,
    "UNCOMPRESSED_DATA": 1,
    "CHECK": 2,                # obsolete/reserved
    "UNCOMPRESSED_FRAGMENTS": 3,
    "NO_FRAGMENTS": 4,
    "ALWAYS_FRAGMENTS": 5,
    "DUPLICATES_REMOVED": 6,   # "NOT duplicated" in some docs; see decode
    "EXPORTABLE": 7,           # EXPORT_TABLE / NFS-exportable; requires lookup_table
    "UNCOMPRESSED_XATTRS": 8,
    "NO_XATTRS": 9,
    "COMPRESSOR_OPTIONS": 10,
    "UNCOMPRESSED_IDS": 11,
}

# EXPORTABLE bit must match whether a lookup table exists at lookup_table_start.
# We currently don't generate one, so we always clear it on write (see
# repacker._write_superblock).

# --- Metadata block ------------------------------------------------------
# Every metadata block (inode table, directory table, fragment/id/xattr
# lookup tables) is prefixed by a 2-byte little-endian header:
#   bit 15       : 1 => block stored uncompressed, 0 => compressed
#   bits 0-14    : on-disk length of the (possibly compressed) payload
# The *decompressed* size of a metadata block is always <= 8192 bytes.
METADATA_BLOCK_HEADER_SIZE = 2
METADATA_UNCOMPRESSED_BIT = 0x8000
METADATA_LENGTH_MASK = 0x7FFF
METADATA_MAX_SIZE = 8192

# --- Fragment table entries ----------------------------------------------
# Each fragment_entry on disk (before being wrapped in metadata blocks) is
# 16 bytes: u64 start_block, u32 size, u32 unused/padding.
FRAGMENT_ENTRY_STRUCT = struct.Struct("<QII")
FRAGMENT_ENTRY_SIZE = FRAGMENT_ENTRY_STRUCT.size
assert FRAGMENT_ENTRY_SIZE == 16

# id table: each entry is a plain 4-byte LE uid/gid value, packed into
# metadata blocks, and then an 8-byte index block of block-start pointers
ID_ENTRY_STRUCT = struct.Struct("<I")
ID_ENTRY_SIZE = ID_ENTRY_STRUCT.size

# index pointer for id/fragment/export "lookup" tables (block starts)
INDEX_PTR_STRUCT = struct.Struct("<Q")
INDEX_PTR_SIZE = INDEX_PTR_STRUCT.size

# export table: one 8-byte inode number -> inode ref per inode
EXPORT_ENTRY_STRUCT = struct.Struct("<Q")
EXPORT_ENTRY_SIZE = EXPORT_ENTRY_STRUCT.size

# --- Compressor options block --------------------------------------------
# Present immediately after the superblock (offset 96) iff the
# COMPRESSOR_OPTIONS flag bit is set. Format is compressor-specific.
COMP_OPTS_GZIP = struct.Struct("<IIH")          # level, window(unused old)/dict, strategies... (varies by version)
COMP_OPTS_XZ = struct.Struct("<II")             # dictionary_size, filters bitmask
COMP_OPTS_LZ4 = struct.Struct("<II")            # version, flags
COMP_OPTS_ZSTD = struct.Struct("<I")            # compression_level
COMP_OPTS_LZO = struct.Struct("<II")            # algorithm, compression_level

# --- Inode types (on-disk, in inode table) --------------------------------
INODE_TYPES = {
    1: "BASIC_DIR",
    2: "BASIC_FILE",
    3: "BASIC_SYMLINK",
    4: "BASIC_BLKDEV",
    5: "BASIC_CHARDEV",
    6: "BASIC_FIFO",
    7: "BASIC_SOCKET",
    8: "EXTENDED_DIR",
    9: "EXTENDED_FILE",
    10: "EXTENDED_SYMLINK",
    11: "EXTENDED_BLKDEV",
    12: "EXTENDED_CHARDEV",
    13: "EXTENDED_FIFO",
    14: "EXTENDED_SOCKET",
}
