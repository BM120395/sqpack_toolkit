"""
metadata_reader.py
===================
SquashFS's inode table and directory table are each a sequence of
"metadata blocks": every block is prefixed by a 2-byte header (length +
compressed flag) and decompresses to at most 8192 bytes. Inode and
directory *references* elsewhere in the filesystem (root_inode, a
directory's start_block/offset, a dir_entry's implied inode location)
are (block_start, offset_within_block) pairs, where block_start is an
absolute file offset pointing at one of these 2-byte headers.

This reader gives random access to that structure: ask for N bytes
starting at any (block_start, offset) pair, and it transparently
decodes just the blocks it needs (cached), following the chain to the
next block on disk when a read crosses a block boundary. It knows
nothing about what the bytes MEAN (that's inode_parser.py /
directory_parser.py) -- it only knows how to get raw decompressed bytes
out of the metadata block chain, which is exactly the layer that needs
to be compressor-agnostic and reusable.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from . import constants as C
from .compressor import decompress_block, CompressorProfile, DecodeError


class MetadataReader:
    def __init__(self, data: bytes, comp_id: int, profile: CompressorProfile = None,
                 xz_options_block: Optional[bytes] = None):
        self.data = data
        self.comp_id = comp_id
        self.profile = profile or CompressorProfile(comp_id)
        self.xz_options_block = xz_options_block
        self._cache: Dict[int, Tuple[bytes, int]] = {}  # block_start -> (decoded, next_block_start)

    def _load_block(self, block_start: int) -> Tuple[bytes, int]:
        if block_start in self._cache:
            return self._cache[block_start]
        if block_start + 2 > len(self.data):
            raise DecodeError(f"Metadata block header at offset {block_start} runs past EOF")
        hdr = int.from_bytes(self.data[block_start:block_start + 2], "little")
        length = hdr & C.METADATA_LENGTH_MASK
        is_compressed = not (hdr & C.METADATA_UNCOMPRESSED_BIT)
        raw = self.data[block_start + 2: block_start + 2 + length]
        if is_compressed:
            # Tolerate trailing zero padding in compressed metadata blocks.
            # A surgical patcher may re-encode a block SHORTER than its
            # original slot and pad the remainder with zeros so the
            # metadata-block chain addresses stay identical. liblzma (used
            # by unsquashfs and the kernel driver) stops at the end-of-
            # stream marker and ignores the trailing padding; a valid XZ
            # stream always ends in the ".xz" footer magic "YZ", never in
            # a zero byte, so stripping trailing NULs only ever removes
            # padding -- never real stream data.
            raw_to_use = raw.rstrip(b"\x00") or raw
            decoded, self.profile = decompress_block(
                raw_to_use, self.comp_id, self.profile, max_size=C.METADATA_MAX_SIZE,
                xz_options_block=self.xz_options_block
            )
        else:
            decoded = raw
        next_block_start = block_start + 2 + length
        self._cache[block_start] = (decoded, next_block_start)
        return self._cache[block_start]

    def read(self, block_start: int, offset: int, length: int) -> Tuple[bytes, int, int]:
        """Read `length` bytes starting at (block_start, offset). Returns
        (data, new_block_start, new_offset) so the caller can continue
        reading sequentially (e.g. for variable-length inode fields)
        without recomputing where it left off."""
        out = bytearray()
        cur_block, cur_off = block_start, offset
        # Safety bound: a single logical read should never need to cross
        # more metadata blocks than the whole file could possibly contain.
        max_hops = max(1, len(self.data) // 2 + 8)
        hops = 0
        while len(out) < length:
            hops += 1
            if hops > max_hops:
                raise DecodeError(
                    f"Metadata read did not terminate after {max_hops} block hops "
                    f"(started at block={block_start}, offset={offset}, wanted {length} bytes) "
                    f"-- likely a corrupt or misinterpreted reference"
                )
            decoded, next_block = self._load_block(cur_block)
            if cur_off > len(decoded):
                raise DecodeError(
                    f"Offset {cur_off} exceeds decoded block size {len(decoded)} "
                    f"at block_start={cur_block}"
                )
            avail = len(decoded) - cur_off
            take = min(avail, length - len(out))
            out += decoded[cur_off:cur_off + take]
            cur_off += take
            if cur_off >= len(decoded):
                cur_block = next_block
                cur_off = 0
        return bytes(out), cur_block, cur_off
