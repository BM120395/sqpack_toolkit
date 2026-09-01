"""
toolcheck.py
============
Answers one narrow, important question up front: "can this tool itself
write this compressor / decode this image?" This matters because it lets
the analyzer flag a hard reproducibility ceiling in Phase 1, before any
repacking is attempted, rather than discovering it after a failed
Phase 3 run.

We deliberately do NOT shell out to any external binary. This tool is
self-contained: encoder introspection is done by exercising our own
encoder module against each known comp_id with a synthetic payload, and
image decode-ability is verified by running our own FilesystemImage +
read_file_content on every file inode. Both checks give us a
verdict that reflects what *this* tool can actually do, on this host,
right now -- which is the only question that matters for a self-
contained repacker.

Historical references to stock mksquashfs / unsquashfs / sasquatch
remain elsewhere in the codebase (comments, docstrings) because they
are useful forensic context for understanding *why* a SquashFS image
looks the way it does -- but the active verification path is entirely
in-house from here on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


log = logging.getLogger(__name__)


@dataclass
class ToolCapability:
    """Snapshot of what this tool can do, right now, on this host.

    Field names are deliberately not versioned-binary-specific: they
    describe what *we* can write/decode, not what some external binary
    happens to advertise.
    """
    encoder_available: bool
    encoder_source: Optional[str]            # e.g. "in-house encoder.py"
    tool_version: Optional[str]              # sqfs_repacker __version__
    supported_write_compressors: List[str]   # names of comp_ids we can WRITE
    check_error: Optional[str] = None
    # Decode-side probe result (populated only by probe_decoding()).
    decode_summary: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# --- Encoder introspection -----------------------------------------------

def _encoder_supports_comp_id(comp_id: int) -> bool:
    """Return True iff our own encoder.encode_block() can write this
    comp_id. Tries a 1-byte synthetic payload; if it raises (anything),
    we can't write that id. This is the authoritative answer for "can
    this tool reproduce a SquashFS image that uses compression id N"."""
    try:
        # Imported lazily so a missing encoder module fails loudly here,
        # not at module-load time (which would block unrelated imports).
        from .compressor import CompressorProfile
        from .encoder import encode_block
        profile = CompressorProfile(comp_id)
        _out, _compressed = encode_block(b"\x00", comp_id, profile)
        return True
    except Exception as e:
        log.debug("encoder does not support comp_id=%d: %s", comp_id, e)
        return False


def probe_encoder(tool_version: Optional[str] = None) -> ToolCapability:
    """Static introspection of this tool's own encoder. Tries every
    known compression id and returns the ones we can write.

    No shell-out, no subprocess, no external dependency. The result
    is a property of the installed code, not of the host's PATH."""
    from . import constants as C
    from . import __version__ as _pkg_version

    version = tool_version or _pkg_version
    supported: List[str] = []
    err: Optional[str] = None
    for cid, name in C.COMPRESSION_IDS.items():
        # Skip "non-standard" sentinel ids (id 0 = NONE is not a real
        # encoder target; we always write whatever the image's comp_id
        # already is, and 0 just means "stored raw").
        if cid == 0:
            continue
        try:
            if _encoder_supports_comp_id(cid):
                # Use the first word as the canonical name (matches the
                # compressor_is_writable contract used downstream).
                short = name.split()[0].lower()
                supported.append(short)
        except Exception as e:
            err = f"comp_id {cid} ({name}) probe raised: {e}"

    return ToolCapability(
        encoder_available=bool(supported),
        encoder_source="in-house encoder.py",
        tool_version=version,
        supported_write_compressors=supported,
        check_error=err,
    )


def compressor_is_writable(compression_name: str, cap: ToolCapability) -> Optional[bool]:
    """Returns True/False if we could determine writability, None if
    unknown. Replaces the old stock-mksquashfs check with an in-house
    encoder introspection lookup."""
    if not cap.encoder_available:
        return None
    return compression_name.lower() in [c.lower() for c in cap.supported_write_compressors]


# --- In-house decode probe -----------------------------------------------

def probe_decoding(image_path: str, max_inodes: Optional[int] = None,
                   timeout_seconds: Optional[float] = None) -> str:
    """Best-effort, empirical check: actually try to decode every file
    in the image using this tool's own FilesystemImage + read_file_content
    (no shell-out, no external binary, no tempdir). The result is a
    single human-readable sentence describing what really happened.

    This is the in-house equivalent of "would stock unsquashfs extract
    this image cleanly?" -- except the answer reflects what *our*
    decoder can do on this host, which is the only question that
    matters for whether Phase 3 will succeed.

    Two very different things can make this fail, and the wording
    distinguishes them so callers can key off the exact substring
    ("DECODE FAILED" vs "skipped device nodes"):

      - a REAL decoding problem (corrupt block, unsupported compressor,
        etc) -- this genuinely means the image (or at least part of it)
        cannot be trusted as fully readable by this tool.

      - a NODE-CREATION limitation (chrdev/blkdev/fifo we can't mknod
        without root, or sockets we never create on disk) -- this
        says nothing about whether the image's DATA is decodable;
        every regular file in the same run typically decodes fine.
        Treating this the same as a real decode failure produces a
        false "this image can't be processed" verdict for images that
        are, in fact, perfectly readable.
    """
    # Lazy imports keep this module importable even when other deps
    # of the package are partially broken (e.g. during incremental
    # development on one module at a time).
    try:
        from .tree import FilesystemImage, iter_nodes
    except Exception as e:
        return f"in-house decoder unavailable -- could not import tree: {e}"

    try:
        fs = FilesystemImage(image_path)
        root = fs.build_tree()
    except Exception as e:
        return f"in-house decoder FAILED to load image ({type(e).__name__}: {e})"

    total = 0
    files_ok = 0
    files_failed: List[dict] = []
    skipped_special: List[dict] = []

    for node in iter_nodes(root):
        total += 1
        if max_inodes is not None and total > max_inodes:
            break
        if node.inode.kind == "file":
            try:
                _content = fs.read_file_content(node.inode)
                files_ok += 1
            except Exception as e:
                files_failed.append({
                    "path": node.path,
                    "kind": node.inode.kind,
                    "error": f"{type(e).__name__}: {e}",
                })
        elif node.inode.kind in ("chrdev", "blkdev", "fifo", "socket"):
            # These are metadata-only inodes; there is no content to
            # decode. The Phase 2 reconstruct() path handles them via
            # sidecar/manifest instead of mknod. We count them as
            # "skipped" so the verdict wording matches the old
            # permission-vs-decode distinction callers depended on.
            skipped_special.append({"path": node.path, "kind": node.inode.kind})

    if not files_failed:
        if skipped_special:
            return (
                f"in-house decoder successfully decoded all readable files "
                f"({files_ok} files OK across {total} inodes; "
                f"{len(skipped_special)} device/fifo/socket node(s) skipped -- "
                f"these are metadata-only and require privileged mknod to "
                f"materialise on disk, which is a host limitation, not a "
                f"decode problem)."
            )
        return (
            f"in-house decoder successfully decoded the full image "
            f"({files_ok} files OK across {total} inodes)."
        )

    # Real decode failure path -- distinguish it from "skipped specials".
    first3 = "; ".join(
        f"{f['path']} ({f['error']})" for f in files_failed[:3]
    )
    return (
        f"in-house decoder FAILED to decode {len(files_failed)}/{files_ok + len(files_failed)} "
        f"file(s) in the image (out of {total} total inodes). "
        f"First failures: {first3}. "
        f"This is a real decode problem -- the affected blocks either use "
        f"unrecognised compression parameters or are genuinely corrupt."
    )
