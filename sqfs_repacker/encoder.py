"""
encoder.py
==========
Phase 3 building block: the inverse of compressor.py. Given a
CompressorProfile (auto-detected in Phase 2) and raw bytes, produces
the compressed on-disk representation using the SAME framing this
specific image already uses.

Why match the vendor framing instead of switching to the stock
reference-compat framing for new content: this image's blocks are
going back onto a real embedded device, and the device's own kernel
driver is what actually has to decode them -- not desktop readers.
Since we've established the whole original image is internally
consistent (every block uses the same lc/lp/pb/dict_size and 5-byte
framing), the safest assumption is that the device's decoder expects
that framing throughout, so newly-written blocks match it too rather
than introducing a second, standard-but-different framing the device
was never built to read. If you point this at an image whose profile
came back "compat13" (a normal reference-built image), new blocks are
written in that framing instead -- the encoder always follows whatever
profile.lzma_framing Phase 2 detected, it does not hardcode one.

SquashFS convention (both for metadata and data/fragment blocks): if
compressing a block does not actually make it smaller than the
original, the block is stored UNCOMPRESSED instead (this is signalled
via the metadata block header's top bit, or the data block-size field's
top bit for data/fragment blocks). We replicate that here -- writing an
incompressible block as "compressed" anyway would be a correctness bug,
not just a missed optimization.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from typing import Tuple

from . import constants as C
from .compressor import CompressorProfile, DecodeError


def _encode_lzma_vendor5(payload: bytes, lc: int, lp: int, pb: int, dict_size: int) -> bytes:
    props_byte = (pb * 5 + lp) * 9 + lc
    filt = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filt)
    body = comp.compress(payload) + comp.flush()
    header = bytes([props_byte]) + struct.pack("<I", dict_size)
    return header + body


def _encode_lzma_compat13(payload: bytes, lc: int, lp: int, pb: int, dict_size: int) -> bytes:
    # Standard reference-compat framing: 5-byte LZMA_alone header + an
    # 8-byte uncompressed-size field (low 4 bytes = real size, high 4
    # bytes = zero), exactly as lzma_xz_wrapper.c writes it, then the raw
    # LZMA1 stream.
    props_byte = (pb * 5 + lp) * 9 + lc
    filt = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filt)
    body = comp.compress(payload) + comp.flush()
    header = bytes([props_byte]) + struct.pack("<I", dict_size) + struct.pack("<I", len(payload)) + b"\x00\x00\x00\x00"
    return header + body


def encode_block(payload: bytes, comp_id: int, profile: CompressorProfile) -> Tuple[bytes, bool]:
    """Compress one block's payload. Returns (bytes_to_write, is_compressed).
    If is_compressed is False, bytes_to_write == payload (stored raw) --
    this happens whenever compression would not actually save space,
    matching real SquashFS behaviour."""
    if not payload:
        return payload, False

    if comp_id == 1:  # gzip/zlib
        compressed = zlib.compress(payload, 9)
        if len(compressed) < len(payload):
            return compressed, True
        return payload, False

    if comp_id == 2:  # legacy LZMA -- follow whatever framing was detected
        # Apply the same safe defaults to BOTH branches -- a profile that
        # named "compat13" framing without populating lc/lp/pb/dict_size
        # would otherwise fall into _encode_lzma_compat13 with Nones and
        # crash at  (pb * 5 + lp) * 9 + lc  with
        #   TypeError: unsupported operand type(s) for *: 'NoneType' and 'int'
        lc = profile.lzma_lc if profile.lzma_lc is not None else 3
        lp = profile.lzma_lp if profile.lzma_lp is not None else 0
        pb = profile.lzma_pb if profile.lzma_pb is not None else 2
        dict_size = profile.lzma_dict_size or (1 << 19)
        if profile.lzma_framing == "compat13":
            compressed = _encode_lzma_compat13(payload, lc, lp, pb, dict_size)
        else:
            # default to vendor5 -- either because that's what was
            # detected, or (no prior detection at all, e.g. building a
            # brand new image) because it's the more compact framing.
            compressed = _encode_lzma_vendor5(payload, lc, lp, pb, dict_size)
        if len(compressed) < len(payload):
            return compressed, True
        return payload, False

    if comp_id == 4:  # XZ
        # CRITICAL: match the original image's XZ check type. Python's
        # lzma.compress() defaults to CRC64 (check=4), but squashfs-tools
        # and most embedded MIPS kernels emit CRC32 (check=1). If we
        # write CRC64, stock readers and the device kernel reject the
        # metadata block with "xz_dec_run error" -> kernel panic.
        #
        # ALSO match the LZMA2 dictionary size. Embedded kernels' SquashFS
        # XZ driver and squashfs-tools allocate a fixed dictionary buffer
        # (from the superblock compressor-options block, typically
        # block_size or smaller) and hand it to xz_dec_run; a stream that
        # declares a larger dictionary than that buffer fails to decode
        # (LZMA_BUF_ERROR / "error code 6"). Python preset=9 requests a
        # 64MiB dictionary unless we explicitly set the size.
        filters = None
        kwargs = dict(format=lzma.FORMAT_XZ, preset=9, check=profile.xz_check)
        if profile.xz_dict_size:
            filters = [{"id": lzma.FILTER_LZMA2, "dict_size": profile.xz_dict_size, "preset": 9}]
            kwargs["filters"] = filters
            kwargs.pop("preset", None)
        compressed = lzma.compress(payload, **kwargs)
        if len(compressed) < len(payload):
            return compressed, True
        return payload, False

    raise DecodeError(
        f"encode_block: writing compression id {comp_id} is not implemented "
        f"(only gzip=1, legacy-lzma=2, xz=4 have encoders here; the image's "
        f"detected compressor must be one of these to repack)."
    )


def encode_metadata_block(payload: bytes, comp_id: int, profile: CompressorProfile) -> bytes:
    """Encode one metadata-table block (<=8192 bytes of logical content)
    into its full on-disk form: the 2-byte length/compressed-flag header
    followed by the (possibly-uncompressed) payload."""
    assert len(payload) <= C.METADATA_MAX_SIZE, "metadata block exceeds 8192 bytes"
    body, is_compressed = encode_block(payload, comp_id, profile)
    length = len(body)
    assert length <= C.METADATA_LENGTH_MASK, "compressed metadata block unexpectedly huge"
    hdr = length | (0 if is_compressed else C.METADATA_UNCOMPRESSED_BIT)
    return struct.pack("<H", hdr) + body


def encode_block_auto(payload: bytes, profiles_by_id: dict) -> Tuple[bytes, int, bool, dict]:
    """`-C auto` building block: try every candidate codec on the same
    payload, return whichever gives the smallest on-disk byte count for
    THIS block.

    Returns: (best_bytes, winning_comp_id, is_compressed, stats)

      - best_bytes         : the compressed bytes to write for this block
                             (or payload itself if nothing compressed well
                             enough -- is_compressed will be False then).
      - winning_comp_id    : which codec won for this block
                             (1=gzip, 2=lzma, 4=xz). Callers that need a
                             SINGLE image-wide codec (SquashFS superblock
                             only names one codec) should tally these and
                             pick the codec with the highest total savings.
      - is_compressed      : True if best_bytes is actually a compressed
                             stream, False if we fell back to storing the
                             raw payload.
      - stats              : {comp_id: compressed_size} for every codec we
                             tried, so the caller can decide which codec
                             to commit to as the image-wide choice.

    Codec selection rule per block:
      1. Try every codec in profiles_by_id.
      2. Any codec whose compressed output is >= payload length is a
         no-op (incompressible); it loses automatically.
      3. Among codecs that did compress, the one with the smallest
         compressed_bytes wins.
      4. If NOTHING compressed, return the raw payload with is_compressed=False
         and winning_comp_id = max(profiles_by_id.keys()) as a stable
         tie-breaker (xz by default; doesn't matter since the block is raw).
    """
    stats: dict = {}
    best_bytes = payload
    best_id = max(profiles_by_id.keys())  # stable default for ties
    best_compressed = False

    for comp_id, profile in profiles_by_id.items():
        try:
            candidate, is_compressed = encode_block(payload, comp_id, profile)
        except Exception:
            # A codec can fail to encode a given payload (rare -- e.g.
            # some random incompressible payload blows up one specific
            # encoder). Treat that as "this codec gives infinity bytes
            # for this block" and move on.
            stats[comp_id] = len(payload) + 1
            continue
        stats[comp_id] = len(candidate)
        if not is_compressed:
            # No codec compresses this block (or this codec's output was
            # >= raw). Keep going to see if another codec compresses it.
            continue
        if len(candidate) < len(best_bytes):
            best_bytes = candidate
            best_id = comp_id
            best_compressed = True

    # If best_compressed is still False, no codec helped -- use raw payload.
    if not best_compressed:
        return payload, best_id, False, stats
    return best_bytes, best_id, True, stats
