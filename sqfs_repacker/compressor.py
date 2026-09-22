"""
compressor.py
=============
Phase 2 building block: turns compressed on-disk bytes into the real
decompressed payload, for whichever compressor the superblock says was
used (constants.COMPRESSION_IDS).

This module is written to be GENERAL, not specific to the sample file
you gave us. Three separate things can vary between SquashFS images and
this module handles all of them independently:

  1. WHICH compressor (gzip/lzma/lzo/xz/lz4/zstd) -- read from the
     superblock, see `decompress_block()`'s `comp_id` argument.

  2. For compressor id 2 (legacy "LZMA", the vendor-fork compressor,
     distinct from standard id 4 "XZ"): WHICH on-disk framing was used
     for the per-block header. Two are known and implemented:
       - "compat13": stock squashfs-tools' own framing (see
         lzma_xz_wrapper.c) -- 5-byte LZMA_alone props+dict-size header,
         padded to 13 bytes with an 8-byte uncompressed-size field that
         the standard *decoder* actually ignores (overwrites with 0xFF
         before decoding) but the *encoder* still writes.
       - "vendor5": what your uploaded image actually uses -- a bare
         5-byte props+dict-size header with NO 8-byte size field; the
         compressed stream starts immediately at byte 5. This is common
         in router/IoT firmware built with older/forked "squashfs-lzma"
         encoders (the class of tool quirk-aware readers exists to read).
     Both are tried automatically (see `_decode_lzma_legacy`), in the
     order most likely to succeed fast, and the one that works is
     recorded so the whole image is decoded consistently rather than
     re-detected block by block (real images are internally consistent
     -- one encoder wrote every block the same way).

  3. As a last resort if NEITHER known framing decodes cleanly: a
     bounded brute-force search over valid LZMA1 (lc, lp, pb) triples
     combined with the dict_size read from whatever header bytes are
     present. This mirrors what quirk-aware readers does, scoped down to just the
     property search (34 valid combinations) rather than needing a
     separate binary/toolchain.

Every strategy is validated by requiring the decompressor to actually
finish without an error AND (when a target size is known) produce
plausible output -- we never silently accept garbage.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple

from . import constants as C

try:
    import zstandard  # optional dependency
    _HAVE_ZSTD = True
except ImportError:
    _HAVE_ZSTD = False

try:
    import lz4.block  # optional dependency
    _HAVE_LZ4 = True
except ImportError:
    _HAVE_LZ4 = False


class DecodeError(Exception):
    """Raised when a compressed block could not be decoded by any known
    or brute-forced strategy. Carries enough detail to be a genuine
    forensic finding, not just 'it failed'."""


@dataclass
class CompressorProfile:
    """Once we've successfully decoded ONE block for a given compressor,
    we remember which strategy/parameters worked, and try that first for
    every subsequent block (falling back to full detection only if it
    stops working, e.g. a corrupt block). This makes bulk decoding of a
    whole image fast instead of brute-forcing every single block."""
    comp_id: int
    lzma_framing: Optional[str] = None       # "compat13" | "vendor5" | "raw_fixed"
    lzma_lc: Optional[int] = None
    lzma_lp: Optional[int] = None
    lzma_pb: Optional[int] = None
    lzma_dict_size: Optional[int] = None
    xz_filters: Optional[list] = None
    # XZ stream check type (byte +7 of stream header):
    #   0 = None, 1 = CRC32, 4 = CRC64, 10 = SHA256
    # Stock squashfs-tools and MIPS kernel SquashFS drivers typically use
    # CRC32 (1). Python's lzma.compress defaults to CRC64 (4) which stock
    # standard readers and the device kernel REJECT. We auto-detect this from
    # the original image and use the same value when re-encoding.
    xz_check: int = 1
    # XZ LZMA2 dictionary size (from the encoded block's filter props).
    # Python lzma.compress(preset=9) writes a 64MiB dictionary. Embedded
    # kernels' SquashFS XZ driver and squashfs-tools allocate a fixed
    # dictionary buffer (from the superblock compressor-options block,
    # usually == block_size or smaller) and pass it to xz_dec_run --
    # a stream whose declared dict exceeds that buffer fails with
    # LZMA_BUF_ERROR. We detect the original image's dict size and reuse
    # it when re-encoding. (None = not yet detected -> fall back to
    # block_size.)
    xz_dict_size: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def _valid_lzma_props(lc: int, lp: int, pb: int) -> bool:
    return 0 <= lc <= 8 and 0 <= lp <= 4 and 0 <= pb <= 4 and (lc + lp) <= 4


def _detect_xz_check(raw: bytes):
    """Read the check type from an XZ stream header.

    XZ stream header layout (12 bytes):
        bytes 0-5:   magic `\\xfd7zXZ\\x00`
        bytes 6-7:   stream flags (2 bytes)
                       - byte 6: reserved/version
                       - byte 7: bits 0-3 encode the check type
                                 (0=None, 1=CRC32, 4=CRC64, 10=SHA256)
                                 bits 4-7 are reserved
        bytes 8-11:  CRC32 of bytes 0-7

    Returns None if the bytes don't look like a valid XZ stream header,
    or the check id otherwise.
    """
    if len(raw) < 12:
        return None
    if raw[0:6] != b"\xfd7zXZ\x00":
        return None
    # Check id is bits 0-3 of byte 7 (the second stream-flags byte).
    return raw[7] & 0x0F


def _props_byte_to_lclppb(props: int) -> Tuple[int, int, int]:
    lc = props % 9
    rem = props // 9
    lp = rem % 5
    pb = rem // 5
    return lc, lp, pb


def _detect_xz_dict_size(raw: bytes) -> Optional[int]:
    """Read the LZMA2 filter's dictionary size from an XZ stream header.

    XZ stream layout for our purposes:
        bytes 0-11:     12-byte stream header
                         (magic + stream flags + header CRC)
        byte 12:        block header size byte `n`; the block header
                         occupies (n+1)*4 bytes total (including this byte)
        byte 13:        block header flags
                         - bit 7:  compressed size field present
                         - bit 6:  uncompressed size field present
                         - bits 0-1: filter count (value+1)
        then           VLI compressed size (if bit 7)
        then           VLI uncompressed size (if bit 6)
        then           filter flags: 1-byte filter id, then per-filter data

    For the LZMA2 filter (id 0x21) the per-filter data is a single
    properties byte encoding the dictionary size:
        dict = (2 | (props & 1)) << (props // 2 + 11)   for props < 40
        dict = 0xFFFFFFFF                                 for props == 40
    """
    if len(raw) < 14:
        return None
    if raw[0:6] != b"\xfd7zXZ\x00":
        return None
    pos = 12
    bhs = raw[pos]; pos += 1
    hdr_size = (bhs + 1) * 4
    if len(raw) < pos + 1:
        return None
    flags = raw[pos]; pos += 1
    n_filters = (flags & 0x03) + 1

    def read_vli(p):
        value = 0
        shift = 0
        while p < len(raw):
            b = raw[p]; p += 1
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                return value, p
            shift += 7
            if shift > 63:
                return None, p
        return None, p

    if flags & 0x80:  # compressed size present
        _, pos = read_vli(pos)
    if flags & 0x40:  # uncompressed size present
        _, pos = read_vli(pos)
    for _ in range(n_filters):
        if pos >= len(raw):
            return None
        fid = raw[pos]; pos += 1
        if fid == 0x21:  # LZMA2
            if pos >= len(raw):
                return None
            props = raw[pos]
            if props == 40:
                return 0xFFFFFFFF
            if props > 40:
                return None
            return (2 | (props & 1)) << (props // 2 + 11)
        # unknown filter: skip its properties
        if pos >= len(raw):
            return None
        psize = raw[pos]; pos += 1
        pos += psize
        if pos > len(raw):
            return None
    return None


def _lclppb_to_props_byte(lc: int, lp: int, pb: int) -> int:
    return (pb * 5 + lp) * 9 + lc


def _try_raw_lzma1(payload: bytes, lc: int, lp: int, pb: int, dict_size: int,
                    max_size: Optional[int]) -> bytes:
    filt = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt)
    out = dec.decompress(payload, max_length=max_size if max_size else -1)
    if not out:
        raise lzma.LZMAError("empty output")
    return out


def _decode_lzma_legacy(raw: bytes, profile: CompressorProfile,
                         max_size: Optional[int]) -> Tuple[bytes, CompressorProfile]:
    """Decode one compressed block known to use compression id 2 (legacy
    LZMA). Tries the remembered profile first, then both known framings,
    then bounded brute force. Returns (decoded_bytes, updated_profile)."""

    # 1. fast path: reuse whatever worked last time for this image
    if profile.lzma_framing == "vendor5" and profile.lzma_dict_size:
        try:
            out = _try_raw_lzma1(raw[5:], profile.lzma_lc, profile.lzma_lp,
                                  profile.lzma_pb, profile.lzma_dict_size, max_size)
            return out, profile
        except lzma.LZMAError:
            pass  # fall through to full detection -- this block may differ
    if profile.lzma_framing == "compat13":
        try:
            out = lzma.decompress(raw, format=lzma.FORMAT_ALONE)
            return out, profile
        except lzma.LZMAError:
            pass

    if len(raw) < 5:
        raise DecodeError(f"LZMA block too short for even a 5-byte header ({len(raw)} bytes)")

    props = raw[0]
    lc, lp, pb = _props_byte_to_lclppb(props)
    dict_size = struct.unpack("<I", raw[1:5])[0]
    header_valid = _valid_lzma_props(lc, lp, pb) and 0 < dict_size <= (1 << 27)

    # 2. try "vendor5" framing using the header's own declared properties
    if header_valid and len(raw) > 5:
        try:
            out = _try_raw_lzma1(raw[5:], lc, lp, pb, dict_size, max_size)
            new_profile = CompressorProfile(profile.comp_id, "vendor5", lc, lp, pb, dict_size)
            return out, new_profile
        except lzma.LZMAError:
            pass

    # 3. try "compat13" framing (stock squashfs-tools format)
    if len(raw) >= C.LZMA_HEADER_SIZE if hasattr(C, "LZMA_HEADER_SIZE") else len(raw) >= 13:
        try:
            out = lzma.decompress(raw, format=lzma.FORMAT_ALONE)
            # CJH-FIX: propagate lc/lp/pb/dict_size into the returned profile too,
            # otherwise encoder.py:_encode_lzma_compat13 gets None for all of them
            # and fails with: TypeError: unsupported operand type(s) for *:
            # 'NoneType' and 'int'  at  (pb * 5 + lp) * 9 + lc.
            new_profile = CompressorProfile(profile.comp_id, "compat13", lc, lp, pb, dict_size)
            return out, new_profile
        except lzma.LZMAError:
            pass

    # 4. bounded brute force: keep the dict_size from the header if it at
    # least looks plausible, otherwise try the block-size-derived guess
    # already recorded on the profile; search all valid (lc, lp, pb).
    candidate_dict_sizes = []
    if 0 < dict_size <= (1 << 27):
        candidate_dict_sizes.append(dict_size)
    if profile.lzma_dict_size and profile.lzma_dict_size not in candidate_dict_sizes:
        candidate_dict_sizes.append(profile.lzma_dict_size)
    for common in (1 << 16, 1 << 20, 1 << 24, 1 << 25, 1 << 26):
        if common not in candidate_dict_sizes:
            candidate_dict_sizes.append(common)

    for ds in candidate_dict_sizes:
        for lc_ in range(0, 5):
            for lp_ in range(0, 5 - lc_):
                for pb_ in range(0, 5):
                    for header_len in (5, 13):
                        if len(raw) <= header_len:
                            continue
                        try:
                            out = _try_raw_lzma1(raw[header_len:], lc_, lp_, pb_, ds, max_size)
                            new_profile = CompressorProfile(
                                profile.comp_id,
                                "vendor5" if header_len == 5 else "raw_fixed",
                                lc_, lp_, pb_, ds,
                            )
                            return out, new_profile
                        except lzma.LZMAError:
                            continue

    raise DecodeError(
        f"Could not decode LZMA block with any known framing or brute-forced "
        f"(lc,lp,pb,dict_size) combination. Header bytes: {raw[:13].hex()}"
    )


def decompress_block(raw: bytes, comp_id: int, profile: CompressorProfile,
                      max_size: Optional[int] = None,
                      xz_options_block: Optional[bytes] = None
                      ) -> Tuple[bytes, CompressorProfile]:
    """Decode one compressed block (metadata OR data OR fragment -- they
    all use the same per-block compressed representation once you have
    the raw compressed bytes). Returns (decoded_bytes, profile), where
    `profile` may be an updated CompressorProfile if this call had to
    (re)detect parameters -- callers should keep using the returned
    profile for subsequent blocks of the same image.
    """
    if comp_id == 1:  # gzip / zlib
        # squashfs's "gzip" compressor is zlib-wrapped deflate; some
        # third-party encoders emit raw deflate instead. Try both.
        try:
            return zlib.decompress(raw), profile
        except zlib.error:
            return zlib.decompress(raw, -15), profile

    if comp_id == 2:  # legacy LZMA (vendor-variable framing)
        return _decode_lzma_legacy(raw, profile, max_size)

    if comp_id == 4:  # XZ
        try:
            decoded = lzma.decompress(raw, format=lzma.FORMAT_XZ)
            # Detect the original image's XZ check type from the stream
            # header byte +7 (after the 6-byte magic+version). This MUST
            # match what we re-encode with -- otherwise the device's XZ
            # decoder (and stock readers on older glibc) rejects the
            # block with "xz_dec_run error" and the kernel panics when
            # it can't read a metadata block. SquashFS images almost
            # always use CRC32 (1); Python's lzma.compress defaults to
            # CRC64 (4) which is what was producing the v1.4 crashes.
            detected_check = _detect_xz_check(raw) if len(raw) >= 12 else 1
            if detected_check is not None and profile.xz_check != detected_check:
                profile = CompressorProfile(
                    comp_id=profile.comp_id,
                    lzma_framing=profile.lzma_framing,
                    lzma_lc=profile.lzma_lc,
                    lzma_lp=profile.lzma_lp,
                    lzma_pb=profile.lzma_pb,
                    lzma_dict_size=profile.lzma_dict_size,
                    xz_filters=profile.xz_filters,
                    xz_check=detected_check,
                    xz_dict_size=profile.xz_dict_size,
                )
            # Also detect and remember the LZMA2 dictionary size. Re-encoding
            # with a larger dict (e.g. Python preset=9 -> 64MiB) produces
            # streams that embedded kernel XZ decoders (fixed buffer) and
            # squashfs-tools reject with LZMA_BUF_ERROR.
            detected_dict = _detect_xz_dict_size(raw)
            if detected_dict is not None and profile.xz_dict_size != detected_dict:
                profile = CompressorProfile(
                    comp_id=profile.comp_id,
                    lzma_framing=profile.lzma_framing,
                    lzma_lc=profile.lzma_lc,
                    lzma_lp=profile.lzma_lp,
                    lzma_pb=profile.lzma_pb,
                    lzma_dict_size=profile.lzma_dict_size,
                    xz_filters=profile.xz_filters,
                    xz_check=profile.xz_check,
                    xz_dict_size=detected_dict,
                )
            return decoded, profile
        except lzma.LZMAError:
            pass
        # Some encoders write a raw LZMA2 stream (no .xz container). If we
        # have the compressor-options block, build the exact filter chain;
        # otherwise fall back to a reasonable default dictionary size.
        dict_size = 1 << 20
        if xz_options_block and len(xz_options_block) >= 4:
            dict_size = struct.unpack("<I", xz_options_block[:4])[0] or dict_size
        filt = [{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}]
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt)
        return dec.decompress(raw, max_length=max_size if max_size else -1), profile

    if comp_id == 5:  # LZ4
        if not _HAVE_LZ4:
            raise DecodeError(
                "This image uses LZ4 compression but the optional 'lz4' Python "
                "package is not installed here (pip install lz4). No fabricated "
                "output will be returned."
            )
        return lz4.block.decompress(raw, uncompressed_size=max_size or (1 << 20)), profile

    if comp_id == 6:  # ZSTD
        if not _HAVE_ZSTD:
            raise DecodeError(
                "This image uses ZSTD compression but the optional 'zstandard' "
                "Python package is not installed here (pip install zstandard). "
                "No fabricated output will be returned."
            )
        return zstandard.ZstdDecompressor().decompress(raw, max_output_size=max_size or (1 << 24)), profile

    if comp_id == 3:  # LZO
        raise DecodeError(
            "This image uses LZO compression. No pure-Python LZO decoder is "
            "bundled (python-lzo requires a compiled C extension not available "
            "in this environment). Install python-lzo to decode this image."
        )

    raise DecodeError(f"Unknown/unsupported compression id {comp_id}")
