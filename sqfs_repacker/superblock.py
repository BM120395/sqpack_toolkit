"""
superblock.py
=============
Parses the fixed 96-byte SquashFS 4.0 superblock and decodes every
field, including the flags bitmask, into a structured, self-documenting
form. This is the foundation everything else in the analyzer builds on:
every table offset the rest of the tool needs comes straight from here.

No inference happens in this module -- it is a pure, literal decode of
what is actually on disk. Inference (e.g. "which mksquashfs flags would
reproduce this") happens later in analyzer.py, kept deliberately
separate so the forensic record always distinguishes "what the file
says" from "what we concluded about it".
"""

from __future__ import annotations

import datetime
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from . import constants as C


class SuperblockError(Exception):
    """Raised when the bytes do not form a well-formed SquashFS 4.x superblock."""


@dataclass
class Superblock:
    # raw fields, exactly as decoded from the struct
    s_magic: int
    inodes: int
    mkfs_time: int
    block_size: int
    fragments: int
    compression: int
    block_log: int
    flags: int
    no_ids: int
    s_major: int
    s_minor: int
    root_inode: int
    bytes_used: int
    id_table_start: int
    xattr_id_table_start: int
    inode_table_start: int
    directory_table_start: int
    fragment_table_start: int
    lookup_table_start: int

    # derived / decoded (populated in __post_init__)
    endian: str = "little"
    compression_name: str = field(default="", repr=True)
    decoded_flags: Dict[str, bool] = field(default_factory=dict)
    active_flag_names: List[str] = field(default_factory=list)
    has_compressor_options: bool = False
    file_size_on_disk: Optional[int] = None
    trailing_bytes: int = 0

    def __post_init__(self):
        self.compression_name = C.COMPRESSION_IDS.get(
            self.compression, f"UNKNOWN(id={self.compression})"
        )
        self.decoded_flags = {
            name: bool(self.flags & (1 << bit))
            for name, bit in C.FLAG_BITS.items()
        }
        self.active_flag_names = [n for n, v in self.decoded_flags.items() if v]
        self.has_compressor_options = self.decoded_flags.get("COMPRESSOR_OPTIONS", False)

    # -- convenience -------------------------------------------------
    @property
    def block_size_from_log(self) -> int:
        """block_size must equal 1 << block_log; both are stored redundantly
        on disk. Mismatch is itself a forensic finding (corruption or a
        non-standard mkfs implementation)."""
        return 1 << self.block_log

    @property
    def mkfs_time_iso(self) -> str:
        try:
            return datetime.datetime.utcfromtimestamp(self.mkfs_time).isoformat() + "Z"
        except (OverflowError, OSError, ValueError):
            return f"<unrepresentable timestamp {self.mkfs_time}>"

    @property
    def table_present(self) -> Dict[str, bool]:
        return {
            "id_table": self.id_table_start != C.SQUASHFS_INVALID_BLK,
            "xattr_id_table": self.xattr_id_table_start != C.SQUASHFS_INVALID_BLK,
            "fragment_table": self.fragment_table_start != C.SQUASHFS_INVALID_BLK and self.fragments > 0,
            "lookup_table (export)": self.lookup_table_start != C.SQUASHFS_INVALID_BLK,
        }

    def integrity_findings(self) -> List[str]:
        """Cross-field sanity checks. Anything appended here is a genuine
        forensic finding, not a guess -- every check is a hard invariant
        the SquashFS format itself guarantees when the image is well-formed."""
        findings = []
        if self.s_magic != C.SQUASHFS_MAGIC:
            findings.append(
                f"MAGIC mismatch: got 0x{self.s_magic:08x}, expected 0x{C.SQUASHFS_MAGIC:08x}"
            )
        if (self.s_major, self.s_minor) != (C.SUPPORTED_MAJOR, C.SUPPORTED_MINOR):
            findings.append(
                f"Version {self.s_major}.{self.s_minor} != supported {C.SUPPORTED_MAJOR}.{C.SUPPORTED_MINOR}"
            )
        if self.block_size != self.block_size_from_log:
            findings.append(
                f"block_size ({self.block_size}) != 1<<block_log ({self.block_size_from_log}) "
                f"-- inconsistent superblock, treat block_log as authoritative"
            )
        if self.compression not in C.COMPRESSION_IDS:
            findings.append(f"Unknown compression id {self.compression}")
        if self.fragments == 0 and self.decoded_flags.get("ALWAYS_FRAGMENTS"):
            findings.append(
                "ALWAYS_FRAGMENTS flag set but fragments==0 -- unusual, verify source mkfs"
            )
        if self.file_size_on_disk is not None:
            if self.bytes_used > self.file_size_on_disk:
                findings.append(
                    f"bytes_used ({self.bytes_used}) exceeds actual file size "
                    f"({self.file_size_on_disk}) -- truncated/corrupt image"
                )
            elif self.bytes_used < self.file_size_on_disk:
                self.trailing_bytes = self.file_size_on_disk - self.bytes_used
                findings.append(
                    f"{self.trailing_bytes} trailing byte(s) after bytes_used "
                    f"(padding, or appended vendor data e.g. dd-style images "
                    f"often pad to an eraseblock or MTD partition boundary)"
                )
        return findings

    def to_dict(self) -> dict:
        d = asdict(self)
        d["compression"] = {"id": self.compression, "name": self.compression_name}
        d["mkfs_time_iso"] = self.mkfs_time_iso
        d["block_size_from_log"] = self.block_size_from_log
        d["table_present"] = self.table_present
        return d


def parse_superblock(data: bytes) -> Superblock:
    """Parse the first SUPERBLOCK_SIZE bytes of `data` into a Superblock.

    Raises SuperblockError if the magic doesn't match a little-endian
    SquashFS 4.x image (big-endian / very old squashfs 1-3 images are out
    of scope for this tool, per the requirement to support v4.x)."""
    if len(data) < C.SUPERBLOCK_SIZE:
        raise SuperblockError(
            f"Input too short for a superblock: {len(data)} < {C.SUPERBLOCK_SIZE} bytes"
        )

    raw = C.SUPERBLOCK_STRUCT.unpack(data[: C.SUPERBLOCK_SIZE])
    values = dict(zip(C.SUPERBLOCK_FIELDS, raw))

    magic = values["s_magic"]
    if magic == C.SQUASHFS_MAGIC_SWAP:
        raise SuperblockError(
            "Detected byte-swapped (big-endian) SquashFS magic. This tool "
            "targets the little-endian v4.x layout produced by mksquashfs/"
            "sasquatch on essentially all modern (MIPS-LE, ARM, x86) "
            "embedded targets; big-endian MIPS images need a separate "
            "code path (not implemented)."
        )
    if magic != C.SQUASHFS_MAGIC:
        raise SuperblockError(
            f"Not a SquashFS image (or unsupported variant): magic=0x{magic:08x}, "
            f"expected 0x{C.SQUASHFS_MAGIC:08x} ('hsqs'). First 16 bytes: "
            f"{data[:16].hex()}"
        )

    sb = Superblock(**values)
    return sb
