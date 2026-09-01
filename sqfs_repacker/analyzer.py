"""
analyzer.py
===========
Phase 1: Analyzer.

Pure, read-only forensic analysis of a SquashFS 4.x image. Produces:
  - a fully decoded superblock
  - a byte-exact region/table layout map
  - integrity findings (things that are objectively true/false about
    the file, not opinions)
  - an inferred "build parameter" summary: our best-effort reconstruction
    of what mksquashfs/sasquatch flags *would* have produced this
    layout, clearly separated from the literal facts above it. These
    flags are documented for human readers and forensic comparison;
    this tool does NOT invoke mksquashfs at runtime -- every byte it
    writes goes through our own encoder module.
  - a reproducibility assessment: can our in-house encoder even write
    this compressor, and can our in-house decoder fully decode this
    image? Both checks are done by exercising the same modules that
    Phase 2/3 rely on, so the verdict reflects exactly what the
    downstream phases will be able to do on this host.

This module does NOT unsquash, decompress inode data, or touch the
filesystem tree -- that is Phase 2 (metadata reconstruction). Keeping
Phase 1 read-only and dependency-light means it can always run, in
environments where no external SquashFS tooling is installed.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import constants as C
from .superblock import Superblock, parse_superblock, SuperblockError
from .layout import Region, build_layout
from .toolcheck import probe_encoder, probe_decoding, compressor_is_writable, ToolCapability


@dataclass
class BuildParameterInference:
    """Best-effort mapping from observed superblock facts to the
    mksquashfs/sasquatch CLI flags that would most plausibly reproduce
    them. Each entry records not just the value but the *reasoning*,
    since that's what makes this useful forensically rather than just
    guessy."""
    inferred: Dict[str, Any] = field(default_factory=dict)
    reasoning: Dict[str, str] = field(default_factory=dict)
    unreproducible: List[str] = field(default_factory=list)

    def set(self, key: str, value: Any, why: str):
        self.inferred[key] = value
        self.reasoning[key] = why

    def flag_unreproducible(self, msg: str):
        self.unreproducible.append(msg)

    def to_dict(self) -> dict:
        return {
            "inferred_parameters": self.inferred,
            "reasoning": self.reasoning,
            "unreproducible_aspects": self.unreproducible,
        }


@dataclass
class AnalysisReport:
    source_path: str
    file_size: int
    sha256: str
    superblock: Superblock
    regions: List[Region]
    integrity_findings: List[str]
    build_params: BuildParameterInference
    tool_capability: ToolCapability
    reproducibility_verdict: str
    analyzed_at: str

    def to_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "analyzed_at": self.analyzed_at,
            "superblock": self.superblock.to_dict(),
            "regions": [r.to_dict() for r in self.regions],
            "integrity_findings": self.integrity_findings,
            "build_parameters": self.build_params.to_dict(),
            "tool_capability": self.tool_capability.to_dict(),
            "reproducibility_verdict": self.reproducibility_verdict,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _infer_build_parameters(sb: Superblock, cap: ToolCapability) -> BuildParameterInference:
    bp = BuildParameterInference()

    bp.set("block_size", sb.block_size, "Read directly from superblock.block_size (== 1<<block_log).")
    bp.set(
        "comp",
        sb.compression_name.split()[0].lower(),
        f"superblock.compression id={sb.compression} decodes to {sb.compression_name}.",
    )

    writable = compressor_is_writable(sb.compression_name.split()[0], cap)
    if writable is False:
        bp.flag_unreproducible(
            f"Compressor '{sb.compression_name}' is not supported by this tool's "
            f"in-house encoder (source: {cap.encoder_source}). The image's comp_id is "
            f"legible but cannot be re-written by us, so byte-identical reproduction "
            f"of a freshly-compressed block is impossible. Either extend the in-house "
            f"encoder with a {sb.compression_name.split()[0].upper()} implementation, "
            f"or -- for an image where the new content is only metadata changes -- rely "
            f"on Phase 3's verbatim-block-copy path (no fresh compression needed for "
            f"unchanged data/fragment blocks)."
        )
    elif writable is None:
        bp.flag_unreproducible(
            "Could not determine whether this tool's in-house encoder supports writing "
            f"'{sb.compression_name}' ({cap.check_error or 'encoder probe did not return a verdict'})."
        )

    if sb.decoded_flags.get("UNCOMPRESSED_INODES"):
        bp.set("noI", True, "NOI flag set: inode table stored uncompressed.")
    if sb.decoded_flags.get("UNCOMPRESSED_DATA"):
        bp.set("noD", True, "NOD flag set: data blocks stored uncompressed.")
    if sb.decoded_flags.get("UNCOMPRESSED_FRAGMENTS"):
        bp.set("noF", True, "NOF flag set: fragments stored uncompressed.")
    if sb.decoded_flags.get("UNCOMPRESSED_XATTRS"):
        bp.set("noX", True, "Xattrs stored uncompressed (uncompressed-xattrs flag set).")
    if sb.decoded_flags.get("UNCOMPRESSED_IDS"):
        bp.set("noId", True, "Uid/gid table stored uncompressed.")

    if sb.decoded_flags.get("NO_FRAGMENTS"):
        bp.set("no-fragments", True, "NO_FRAGMENTS flag set: tail-end packing into fragments disabled entirely.")
    elif sb.decoded_flags.get("ALWAYS_FRAGMENTS"):
        bp.set("always-use-fragments", True, "ALWAYS_FRAGMENTS flag set: fragments used even for blocks that fill exactly.")

    if not sb.decoded_flags.get("DUPLICATES_REMOVED"):
        bp.set("no-duplicates", True, "DUPLICATES_REMOVED flag is CLEAR: source mkfs ran with duplicate detection disabled.")
    else:
        bp.reasoning["duplicates"] = "DUPLICATES_REMOVED flag set: default dedup behaviour (mksquashfs default; no flag needed to reproduce)."

    if sb.decoded_flags.get("EXPORTABLE"):
        bp.set("exportable", True, "EXPORT flag set: NFS export table present (mksquashfs default is ON; -no-exports would clear it).")
    else:
        bp.set("no-exports", True, "EXPORT flag clear.")

    if sb.decoded_flags.get("NO_XATTRS"):
        bp.set("no-xattrs", True, "NO_XATTRS flag set / xattr_id_table_start invalid: image built with xattrs stripped.")

    bp.reasoning["mkfs_time"] = (
        f"superblock.mkfs_time={sb.mkfs_time} ({sb.mkfs_time_iso}). mksquashfs stamps "
        f"the CURRENT time by default; reproducing this exact value requires explicit "
        f"'-fstime {sb.mkfs_time}' (or '-all-time'/'-mkfs-time' depending on version), "
        f"otherwise every repack changes this field and therefore the image hash even "
        f"when all file content is identical -- this is the single most common cause "
        f"of 'different hash, same files'."
    )

    if sb.trailing_bytes:
        bp.reasoning["padding"] = (
            f"{sb.trailing_bytes} byte(s) exist after bytes_used. Could be mksquashfs's "
            f"own block-alignment padding, or (very common for router firmware pulled "
            f"via `dd`) trailing padding/appended data introduced by the raw flash dump "
            f"itself, unrelated to mksquashfs. Reproducing it exactly requires appending "
            f"the same trailing bytes post-hoc; mksquashfs has no flag for arbitrary "
            f"vendor padding."
        )

    return bp


def _reproducibility_verdict(bp: BuildParameterInference, sb: Superblock, findings: List[str]) -> str:
    vendor_lzma = [f for f in findings if "VENDOR-SPECIFIC LZMA" in f]
    # "in-house decoder FAILED" is a real decode failure (see toolcheck.py's
    # probe_decoding -- device-node-skip wording never contains this
    # substring). It only implies an LZMA framing problem when the image is
    # actually LZMA-compressed (id 2); for any other compressor, a decode
    # failure means something else entirely and must not trigger LZMA-
    # specific advice.
    extraction_failed = any("in-house decoder FAILED" in f for f in findings)
    if vendor_lzma or (extraction_failed and sb.compression == 2):
        return (
            "BLOCKED before Phase 2 can even begin: this tool's in-house decoder could not "
            "fully decode this image on this host (empirically verified, see findings above), "
            "which means at least some data/fragment/metadata blocks use LZMA properties or "
            "framing that the conventional legacy-LZMA compat reader does not handle. Byte-"
            "identical repacking is impossible until the true per-block LZMA properties are "
            "recovered -- most likely via a brute-force search over valid (lc, lp, pb, "
            "dict_size) combinations per block, which Phase 2 (metadata reconstruction) should "
            "implement rather than assuming the header-decoded properties shown above are "
            "what every block actually used. The superblock-level parameters below are still "
            "correct and will still be needed once decoding works."
        )
    if extraction_failed:
        # Real decode failure, but NOT LZMA (e.g. a genuinely corrupt XZ
        # block, or a compressor this in-house decoder doesn't support
        # at all) -- still worth a clear verdict, just not the LZMA-
        # specific brute-force advice above, which would be actively
        # misleading for a non-LZMA image.
        return (
            "BLOCKED before Phase 2 can even begin: this tool's in-house decoder could not "
            "fully decode this image on this host (empirically verified, see findings above). "
            f"This is NOT an LZMA framing issue (compression id={sb.compression}, "
            f"{sb.compression_name}) -- the actual cause is in the extraction findings above "
            "and needs its own investigation before Phase 2/3 can be trusted on this specific "
            "image."
        )
    if bp.unreproducible:
        return (
            "NOT byte-identically reproducible with this tool's current encoder as-is. "
            + " | ".join(bp.unreproducible)
        )
    return (
        "Superblock-level parameters appear fully reproducible with this tool's in-house "
        "encoder (pending Phase 2/3 verification of inode ordering, fragment packing order, "
        "and id/xattr table contents, none of which are fully determined by the superblock "
        "alone)."
    )


def _lzma_stream_fingerprint(sb: Superblock, data: bytes) -> Optional[str]:
    """For LZMA-compressed (compression id 2) images, peek the very first
    metadata block (the start of the inode table) and check whether it
    looks like the "legacy squashfs-lzma compat" framing that stock
    squashfs-tools' reader expects: 1 props byte encoding (lc,lp,pb) via
    props = (pb*5+lp)*9+lc, followed by a 4-byte little-endian dictionary
    size, then raw LZMA-compressed bytes.

    This is a real, working diagnostic (not a guess): if the decoded
    lc/lp/pb triple is outside LZMA's valid ranges (lc<=8, lp<=4,
    lc+lp<=4, pb<=4) or the dictionary size is absurd (e.g. far bigger
    than the whole file), the block does NOT use that framing, which
    means a different/vendor-specific LZMA header layout is in play --
    exactly the class of image sasquatch's brute-force LZMA-options
    resolver exists to handle, and exactly why the user's own prompt
    named unsquashfs *or* sasquatch as extraction options.
    """
    if sb.compression != 2:  # only meaningful for legacy LZMA
        return None
    # inode_table_start is authoritative (straight from the superblock) --
    # no need to derive it; it is NOT generally == 96, since the data and
    # fragment block area sits between the superblock and the inode table.
    off = sb.inode_table_start
    if off + 2 > len(data):
        return None
    hdr = int.from_bytes(data[off:off + 2], "little")
    is_compressed = not (hdr & C.METADATA_UNCOMPRESSED_BIT)
    length = hdr & C.METADATA_LENGTH_MASK
    block = data[off + 2: off + 2 + length]
    if not is_compressed or len(block) < 5:
        return None

    props = block[0]
    lc = props % 9
    rem = props // 9
    lp = rem % 5
    pb = rem // 5
    import struct
    dict_size = struct.unpack("<I", block[1:5])[0]

    valid_props = (lc <= 8 and lp <= 4 and (lc + lp) <= 4 and pb <= 4)
    valid_dict = 0 < dict_size <= max(len(data) * 4, 1 << 26)

    if valid_props and valid_dict:
        return (
            f"First inode-table metadata block at offset {off} decodes as a standard "
            f"legacy-LZMA header: lc={lc} lp={lp} pb={pb}, dict_size={dict_size}. "
            f"Framing looks like the conventional squashfs-lzma compat layout."
        )
    return (
        f"First inode-table metadata block at offset {off} does NOT decode as the "
        f"conventional legacy-LZMA header (props byte=0x{props:02x} -> lc={lc},lp={lp},"
        f"pb={pb} [valid={valid_props}], dict_size={dict_size} [plausible={valid_dict}]). "
        f"This indicates a VENDOR-SPECIFIC LZMA options/framing variant rather than the "
        f"standard compat format. Resolving the real per-block LZMA properties (likely via "
        f"brute-force search over valid lc/lp/pb/dict_size combinations, the technique used "
        f"by legacy sasquatch-style readers) is a prerequisite for Phase 2 (metadata "
        f"reconstruction) on this specific image."
    )


def analyze(path: str) -> AnalysisReport:
    with open(path, "rb") as f:
        data = f.read()

    file_size = len(data)
    digest = hashlib.sha256(data).hexdigest()

    try:
        sb = parse_superblock(data)
    except SuperblockError as e:
        raise

    sb.file_size_on_disk = file_size
    findings = sb.integrity_findings()

    lzma_fingerprint = _lzma_stream_fingerprint(sb, data)
    if lzma_fingerprint:
        findings.append(lzma_fingerprint)

    extraction_result = probe_decoding(path)
    findings.append(f"Empirical in-house decode test (FilesystemImage + read_file_content): {extraction_result}")

    if "skipped device/fifo/socket" in extraction_result:
        findings.append(
            "NOTE: the skipped device/fifo/socket node(s) above are a host LIMITATION -- "
            "they are metadata-only inodes that need privileged mknod to materialise on "
            "disk, which is irrelevant to whether the image's data is decodable. Every other "
            "file in the image decodes normally, and this tool's own Phase 2/3 preserve "
            "device/fifo/socket inodes without needing to create the actual node on disk "
            "(they are recorded via the sidecar manifest), so this limitation does not "
            "block repacking."
        )
    elif "in-house decoder FAILED" in extraction_result and sb.compression == 2:
        findings.append(
            "NOTE: the first inode-table metadata block's LZMA header can look like the "
            "standard legacy-compat framing (see above) while decoding still fails deeper "
            "into the file -- e.g. if the per-block stored lc/lp/pb/dict-size differ from "
            "the compat defaults, any block whose real properties differ from those "
            "defaults will fail to decode even though its header 'looks' well-formed. This "
            "must be verified against the actual failing block's properties in Phase 2, "
            "not assumed."
        )

    regions = build_layout(sb, data)

    cap = probe_encoder()
    cap.decode_summary = extraction_result
    build_params = _infer_build_parameters(sb, cap)
    verdict = _reproducibility_verdict(build_params, sb, findings)

    return AnalysisReport(
        source_path=os.path.abspath(path),
        file_size=file_size,
        sha256=digest,
        superblock=sb,
        regions=regions,
        integrity_findings=findings,
        build_params=build_params,
        tool_capability=cap,
        reproducibility_verdict=verdict,
        analyzed_at=datetime.datetime.utcnow().isoformat() + "Z",
    )


def format_forensic_log(report: AnalysisReport) -> str:
    """Human-readable verbose forensic log (requirement #10)."""
    sb = report.superblock
    lines = []
    a = lines.append
    a("=" * 78)
    a("SQUASHFS DETERMINISTIC REPACKER -- PHASE 1: ANALYZER FORENSIC LOG")
    a("=" * 78)
    a(f"Source file        : {report.source_path}")
    a(f"File size           : {report.file_size} bytes")
    a(f"SHA-256 (whole file): {report.sha256}")
    a(f"Analyzed at (UTC)   : {report.analyzed_at}")
    a("")
    a("-- SUPERBLOCK (literal, decoded) " + "-" * 40)
    a(f"  magic              : 0x{sb.s_magic:08x} ({'OK' if sb.s_magic == C.SQUASHFS_MAGIC else 'MISMATCH'})")
    a(f"  version             : {sb.s_major}.{sb.s_minor}")
    a(f"  inodes              : {sb.inodes}")
    a(f"  mkfs_time           : {sb.mkfs_time} ({sb.mkfs_time_iso})")
    a(f"  block_size          : {sb.block_size} (block_log={sb.block_log}, 1<<block_log={sb.block_size_from_log})")
    a(f"  fragments           : {sb.fragments}")
    a(f"  compression         : id={sb.compression} -> {sb.compression_name}")
    a(f"  flags (raw)         : 0x{sb.flags:04x}")
    for name, val in sb.decoded_flags.items():
        a(f"      {name:<24}: {val}")
    a(f"  no_ids (uid/gid ct) : {sb.no_ids}")
    a(f"  root_inode          : 0x{sb.root_inode:016x} (block={sb.root_inode >> 16}, offset={sb.root_inode & 0xffff})")
    a(f"  bytes_used          : {sb.bytes_used}")
    a(f"  id_table_start      : {sb.id_table_start if sb.id_table_start != C.SQUASHFS_INVALID_BLK else '(none)'}")
    a(f"  xattr_id_table_start: {sb.xattr_id_table_start if sb.xattr_id_table_start != C.SQUASHFS_INVALID_BLK else '(none)'}")
    a(f"  inode_table_start   : {sb.inode_table_start}")
    a(f"  directory_table_start: {sb.directory_table_start}")
    a(f"  fragment_table_start: {sb.fragment_table_start if sb.fragment_table_start != C.SQUASHFS_INVALID_BLK else '(none)'}")
    a(f"  lookup_table_start  : {sb.lookup_table_start if sb.lookup_table_start != C.SQUASHFS_INVALID_BLK else '(none / not exported)'}")
    a("")
    a("-- INTEGRITY FINDINGS " + "-" * 50)
    if report.integrity_findings:
        for f in report.integrity_findings:
            a(f"  [!] {f}")
    else:
        a("  (none -- superblock is internally consistent)")
    a("")
    a("-- REGION / TABLE LAYOUT MAP " + "-" * 40)
    a(f"  {'region':<26}{'start':>10}{'end':>10}{'size':>10}  sha256")
    for r in report.regions:
        a(f"  {r.name:<26}{r.start:>10}{r.end:>10}{r.size:>10}  {r.sha256}")
    a("")
    a("-- HOST TOOL CAPABILITY (in-house) " + "-" * 38)
    cap = report.tool_capability
    a(f"  in-house encoder available : {cap.encoder_available} ({cap.encoder_source})")
    a(f"  sqfs_repacker version       : {cap.tool_version}")
    a(f"  writable compressors        : {cap.supported_write_compressors}")
    if cap.check_error:
        a(f"  check_error                 : {cap.check_error}")
    if cap.decode_summary:
        a(f"  decode summary              : {cap.decode_summary}")
    a("")
    a("-- INFERRED BUILD PARAMETERS " + "-" * 39)
    for k, v in report.build_params.inferred.items():
        why = report.build_params.reasoning.get(k, "")
        a(f"  {k} = {v}")
        if why:
            a(f"      reason: {why}")
    extra_reasoning = {
        k: v for k, v in report.build_params.reasoning.items()
        if k not in report.build_params.inferred
    }
    for k, why in extra_reasoning.items():
        a(f"  ({k}): {why}")
    a("")
    a("-- REPRODUCIBILITY VERDICT " + "-" * 41)
    for chunk in report.reproducibility_verdict.split(" | "):
        a(f"  {chunk}")
    a("=" * 78)
    return "\n".join(lines)
