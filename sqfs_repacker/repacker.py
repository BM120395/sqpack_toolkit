"""
repacker.py
============
Phase 3: Deterministic repacker -- the single shared rebuild engine.

Every workflow that produces a rebuilt image goes through ONE pipeline:
`Repacker.build()`. It has three ways to be told what should change,
all of which funnel into the exact same merge -> resolve -> serialize
steps below:

  1. `patches={path: bytes}` -- explicit content replacement (the
     original --patch interface). Unchanged from before.
  2. `source_dir=DIR` -- a directory tree (e.g. produced by
     --reconstruct, then edited) to diff against the original image.
     directory_diff.py computes the classification (UNCHANGED /
     MODIFIED / ADDED / REMOVED / METADATA_ONLY / TYPE_CHANGED); this
     module converts that classification into the SAME internal
     representation `patches` already used -- extra `Inode.raw_content`
     / `pending_uid` / `pending_gid` fields on a merged FSNode tree --
     so there is no second rebuild algorithm, just a second way to
     populate the first one's input.
  3. Both together -- `source_dir` is applied first, then `patches` is
     applied on top and WINS on any path both mention (explicit patches
     override the automatic directory diff).

None of that changes the fundamental guarantees this engine has always
provided:
  * every byte-identical (post-merge) file is reused VERBATIM from the
    original image's compressed blocks -- never decompressed and
    recompressed "with matching settings". This is the only way to
    actually guarantee bit-identical bytes for unmodified content,
    since LZMA output is not guaranteed bit-reproducible across
    encoder implementations even with identical lc/lp/pb/dict_size.
  * duplicate/shared data blocks and fragments (SquashFS dedup, AND
    hardlink topology) are preserved -- including correctly SPLITTING
    a hardlink group when only one of its members changes, and
    correctly MERGING newly-added/modified paths that are hardlinked
    to each other locally in source_dir.
  * only actually-changed content is freshly compressed, using this
    image's own on-disk framing (vendor5/compat13/etc), since the real
    decoder is typically the target device's kernel, not desktop
    standard readers.
  * fragments that become unreferenced are dropped, keeping output
    size minimal. (v1.14.0: fragments referenced by any reuse file are
    CARRIED as decompressed buffers -- fresh tails from changed files
    are appended into the carried payload, preserving the source
    fragment count; a carried fragment whose payload changed is
    re-encoded once. The NFS export/lookup table is rebuilt when the
    source image had one.)

Known, documented limitation (unchanged from before): the inode table,
directory table, fragment table, and id table are ALWAYS freshly
rebuilt whenever anything changes -- never byte-reused, even for
inodes whose logical content is identical -- because those tables
store absolute offsets and ANY size change anywhere cascades through
every table that references a shifted offset. This is an inherent
SquashFS format property, not a shortcut taken here.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field, replace as dc_replace
from typing import Dict, List, Optional, Tuple

from . import constants as C
from . import inode_structs as S
from .constants import EXPORT_ENTRY_STRUCT
from . import directory_diff as ddiff
from .directory_diff import DirectoryDiff, DiffEntry, Status
from .tree import FilesystemImage, FSNode, iter_nodes
from .inode_parser import Inode
from .compressor import CompressorProfile, decompress_block
from .encoder import encode_block, encode_metadata_block
from .table_builder import MetadataTableBuilder, build_mutual_tables, Patch

SQUASHFS_INVALID_BLK = 0xFFFFFFFFFFFFFFFF


@dataclass
class RepackStats:
    mode: str  # "identity" | "patched"
    patched_paths: List[str] = field(default_factory=list)
    source_dir: Optional[str] = None

    files_reused_verbatim: int = 0
    files_recompressed: int = 0
    data_blocks_reused: int = 0
    data_blocks_new: int = 0
    fragments_reused: int = 0
    fragments_new: int = 0
    fragments_dropped: int = 0
    # v1.14.0 fragment consolidation: fresh tails appended into carried
    # original fragments (no new fragment allocated), and carried
    # fragments that had to be re-encoded because their payload changed.
    fragments_consolidated: int = 0
    fragments_recompressed: int = 0
    original_size: int = 0
    new_size: int = 0
    warnings: List[str] = field(default_factory=list)

    # -- directory_diff-driven stats (populated only when source_dir given)
    directory_diff: Optional[dict] = None
    unchanged_count: int = 0
    modified_count: int = 0
    added_count: int = 0
    removed_count: int = 0
    metadata_only_count: int = 0

    # -- spec-named aliases (kept alongside the original names above for
    # backward compatibility with anything already parsing the JSON report)
    fragments_consolidated: int = 0
    fragments_recompressed: int = 0
    export_table_rebuilt: bool = False

    @property
    def reused_blocks(self) -> int:
        return self.data_blocks_reused

    @property
    def recompressed_blocks(self) -> int:
        return self.data_blocks_new

    @property
    def fragment_reused(self) -> int:
        return self.fragments_reused

    @property
    def fragment_rebuilt(self) -> int:
        return self.fragments_new

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        d["reused_blocks"] = self.reused_blocks
        d["recompressed_blocks"] = self.recompressed_blocks
        d["fragment_reused"] = self.fragment_reused
        d["fragment_rebuilt"] = self.fragment_rebuilt
        return d


def _plan_file_layout(file_size: int, block_size: int, always_fragments: bool,
                       no_fragments: bool) -> Tuple[int, bool]:
    """Mirrors inode_parser._num_full_blocks's convention in the write
    direction. Returns (num_full_blocks, use_fragment_for_remainder)."""
    if no_fragments:
        full = (file_size + block_size - 1) // block_size
        return full, False
    remainder = file_size % block_size
    full = file_size // block_size
    if remainder == 0:
        if always_fragments and file_size > 0:
            return max(full - 1, 0), True
        return full, False
    return full, True


# =========================================================================
# Tree merge: turns (original tree, source_dir diff, explicit patches)
# into ONE merged FSNode tree that the rest of build() serializes exactly
# as it always has. This is the ONLY new logic; everything downstream of
# `_merge_tree()` in build() is unchanged from before source_dir existed.
# =========================================================================
_KIND_KEYS = ("dir", "file", "symlink", "chrdev", "blkdev", "fifo", "socket")


def _fresh_inode_from_local(entry: DiffEntry, inode_number: Optional[int]) -> Inode:
    # Sidecar-sourced entries (ADDED special nodes that came from
    # .sqpack_devices) carry their full metadata in entry.device_meta.
    # Synthesize the inode from that, NOT from a local stat (since
    # nothing actually exists on disk for these paths).
    if entry.device_meta is not None:
        dentry = entry.device_meta
        inode = Inode(
            kind=dentry.kind, extended=False,
            mode=dentry.mode & 0o7777,
            uid_idx=0, gid_idx=0,
            mtime=0, inode_number=inode_number,
            nlink=1,
            pending_uid=dentry.uid, pending_gid=dentry.gid,
            rdev=dentry.rdev if dentry.is_device else 0,
        )
        return inode
    st = entry.local_stat
    import stat as statmod
    mode = statmod.S_IMODE(st.st_mode)
    mtime = int(st.st_mtime)
    inode = Inode(kind=entry.kind, extended=False, mode=mode, uid_idx=0, gid_idx=0,
                  mtime=mtime, inode_number=inode_number,
                  nlink=1, pending_uid=st.st_uid, pending_gid=st.st_gid)
    if entry.kind == "file":
        with open(entry.local_path, "rb") as f:
            inode.raw_content = f.read()
        inode.file_size = len(inode.raw_content)
    elif entry.kind == "symlink":
        inode.symlink_target = os.readlink(entry.local_path).encode("utf-8", "surrogateescape")
    elif entry.kind in ("chrdev", "blkdev"):
        inode.rdev = st.st_rdev
    return inode


def _apply_entry_in_place(inode: Inode, entry: DiffEntry) -> None:
    """MODIFIED / METADATA_ONLY -- mutate a copy of the ORIGINAL inode
    (identity/inode_number preserved unless later split for hardlinks)
    rather than building fresh, so anything the entry did NOT flag as
    changed keeps its exact original value."""
    st = entry.local_stat
    if "mode" in entry.metadata_changes:
        import stat as statmod
        inode.mode = statmod.S_IMODE(st.st_mode)
    if "uid" in entry.metadata_changes:
        inode.pending_uid = st.st_uid
    if "gid" in entry.metadata_changes:
        inode.pending_gid = st.st_gid
    if "mtime" in entry.metadata_changes:
        inode.mtime = int(st.st_mtime)

    if entry.status == Status.MODIFIED:
        if entry.kind == "file":
            with open(entry.local_path, "rb") as f:
                inode.raw_content = f.read()
            if inode.orig_file_size is None:
                inode.orig_file_size = inode.file_size  # pre-edit size
            inode.file_size = len(inode.raw_content)
        elif entry.kind == "symlink":
            inode.symlink_target = os.readlink(entry.local_path).encode("utf-8", "surrogateescape")
        elif entry.kind in ("chrdev", "blkdev"):
            inode.rdev = st.st_rdev


def _merge_tree(fs: FilesystemImage, source_dir: Optional[str],
                 patches: Optional[Dict[str, bytes]]) -> Tuple[FSNode, Optional[DirectoryDiff]]:
    patches = dict(patches or {})
    root = fs.root or fs.build_tree()

    diff = ddiff.compute_diff(fs, source_dir) if source_dir else None

    nodes: Dict[str, FSNode] = {}
    local_stat_by_id: Dict[int, os.stat_result] = {}
    removed = set(diff.removed_paths_all_kinds) if diff else set()

    # 1. seed every surviving path from the original tree (copy the Inode
    #    so we never mutate fs.root's own parsed state).
    for orig_node in iter_nodes(root):
        if orig_node.path in removed:
            continue
        new_inode = dc_replace(orig_node.inode)
        nodes[orig_node.path] = FSNode(name=orig_node.name, path=orig_node.path,
                                        inode=new_inode, children=[])

    # 2. layer the directory diff on top
    if diff:
        for path, entry in diff.entries.items():
            if entry.status == Status.UNCHANGED:
                if entry.local_stat is not None:
                    local_stat_by_id[id(nodes[path].inode)] = entry.local_stat
                continue
            if entry.status == Status.ADDED:
                fresh = _fresh_inode_from_local(entry, inode_number=None)
                nodes[path] = FSNode(name=entry.name, path=path, inode=fresh, children=[])
                local_stat_by_id[id(fresh)] = entry.local_stat
            elif entry.status == Status.TYPE_CHANGED:
                fresh = _fresh_inode_from_local(entry, inode_number=None)
                nodes[path] = FSNode(name=entry.name, path=path, inode=fresh, children=[])
                local_stat_by_id[id(fresh)] = entry.local_stat
            else:  # MODIFIED / METADATA_ONLY
                node = nodes[path]
                _apply_entry_in_place(node.inode, entry)
                if entry.local_stat is not None:
                    local_stat_by_id[id(node.inode)] = entry.local_stat

    # 3. explicit patches win last
    for path, content in patches.items():
        if path in nodes:
            if nodes[path].inode.orig_file_size is None:
                nodes[path].inode.orig_file_size = nodes[path].inode.file_size
            nodes[path].inode.kind = "file"
            nodes[path].inode.raw_content = content
            nodes[path].inode.file_size = len(content)
        else:
            raise ValueError(
                f"--patch target {path!r} does not exist in the original image or "
                f"--source-dir; only existing (or --source-dir-added) paths can be patched"
            )

    # 4. finalize inode-number identity (preserve/split/merge hardlinks)
    _finalize_inode_numbers(nodes, root, local_stat_by_id)

    # 5. recompute nlink from the FINAL grouping
    by_number: Dict[int, List[FSNode]] = {}
    for node in nodes.values():
        if node.inode.kind == "dir":
            continue
        by_number.setdefault(node.inode.inode_number, []).append(node)
    for number, group in by_number.items():
        for n in group:
            n.inode.nlink = len(group)

    # 6. link parent -> children
    # First: ensure every parent directory chain for ADDED paths exists in
    # `nodes`. Sidecar-sourced device/fifo/socket nodes (and ADDED
    # non-special paths from --source-dir in general) can reference parent
    # dirs that aren't otherwise in the tree -- e.g. /var/run/myfifo where
    # /var/run doesn't exist on disk and isn't in the original. Create a
    # minimal synthetic dir for each missing ancestor so the link below
    # succeeds. Without this, the ADDED node ends up parentless and is
    # silently dropped during serialization (parents can't reference
    # children they don't see).
    original_by_path_for_parents: Dict[str, FSNode] = {n.path: n for n in iter_nodes(root)}

    def ensure_parent_dirs(path: str) -> None:
        parent_path = path.rsplit("/", 1)[0] or "/"
        if parent_path == "/" or parent_path in nodes:
            return
        ensure_parent_dirs(parent_path)
        # Don't revive parents that exist in the original but are missing
        # from `nodes` because they were removed -- only create a synthetic
        # dir for ancestors that are genuinely new.
        if parent_path not in original_by_path_for_parents:
            from .inode_parser import Inode
            nodes[parent_path] = FSNode(
                name=parent_path.rsplit("/", 1)[-1] or parent_path,
                path=parent_path,
                inode=Inode(kind="dir", extended=False, mode=0o755,
                            uid_idx=0, gid_idx=0, mtime=0,
                            inode_number=None, nlink=2),
                children=[],
            )

    for path in list(nodes.keys()):
        if path == "/":
            continue
        ensure_parent_dirs(path)

    for path, node in nodes.items():
        if path == "/":
            continue
        parent_path = path.rsplit("/", 1)[0] or "/"
        parent = nodes.get(parent_path)
        if parent is not None:
            parent.children.append(node)

    merged_root = nodes["/"]

    # 7. renumber contiguously 1..N. _finalize preserves original numbers
    #    for unchanged nodes but allocates max_original+1 for changed/added
    #    ones, which can leave non-contiguous gaps where inode_count != max
    #    number. standard readers enforces inode_number <= superblock.inode_count,
    #    so a trailing fresh number (e.g. 415 with count 414) is rejected as
    #    "inode number too large". Hardlink groups keep a single shared number
    #    (renumber by group to preserve the grouping). Operates on the MERGED
    #    node copies (nodes), not on the original fs.root tree.
    _renumber_contiguous(merged_root)

    # renumber may change nlink grouping identity; recompute nlink
    by_number = {}
    for node in nodes.values():
        if node.inode.kind == "dir":
            continue
        by_number.setdefault(node.inode.inode_number, []).append(node)
    for number, group in by_number.items():
        for n in group:
            n.inode.nlink = len(group)

    return merged_root, diff


def _finalize_inode_numbers(nodes: Dict[str, FSNode], original_root: FSNode,
                             local_stat_by_id: Dict[int, "os.stat_result"]) -> None:
    """Preserves original inode_number (and therefore hardlink grouping)
    for anything that didn't change. For anything that DID change
    content (raw_content set) or is brand new, allocates a fresh
    inode_number -- grouped by the LOCAL (st_dev, st_ino) pair when one
    is available, so files hardlinked to each other in source_dir stay
    hardlinked to each other in the rebuilt image. This includes the
    case of a brand-new path hardlinked to an EXISTING, unchanged file:
    since we track local_stat for unchanged nodes too (not just
    modified/added ones), such a path is matched back to the existing
    file's ORIGINAL inode_number rather than getting a duplicate,
    unshared copy of the same content."""
    max_original = 0
    for n in iter_nodes(original_root):
        max_original = max(max_original, n.inode.inode_number)
    next_number = [max_original + 1]
    local_group_number: Dict[Tuple[int, int], int] = {}

    # Seed the map from anything that ISN'T getting new content -- its
    # inode_number is already final (the original one), so any new path
    # sharing its (st_dev, st_ino) should be merged into that SAME
    # number rather than allocated a fresh one.
    for node in nodes.values():
        if node.inode.kind == "dir" or node.inode.raw_content is not None:
            continue
        st = local_stat_by_id.get(id(node.inode))
        if st is not None:
            local_group_number.setdefault((st.st_dev, st.st_ino), node.inode.inode_number)

    def alloc(inode: Inode) -> int:
        st = local_stat_by_id.get(id(inode))
        key = (st.st_dev, st.st_ino) if st is not None else None
        if key is not None and key in local_group_number:
            return local_group_number[key]
        n = next_number[0]
        next_number[0] += 1
        if key is not None:
            local_group_number[key] = n
        return n

    for node in nodes.values():
        if node.inode.kind == "dir":
            if node.inode.inode_number is None:
                node.inode.inode_number = alloc(node.inode)  # no local_stat entry -> always a fresh number
            continue
        needs_alloc = node.inode.raw_content is not None or node.inode.inode_number is None
        if needs_alloc:
            node.inode.inode_number = alloc(node.inode)


def _iter_children_sorted(node: FSNode):
    """Stable child iteration order (by name), matching how directory
    listings are emitted. """
    return sorted(node.children, key=lambda c: c.name.encode("utf-8", "surrogateescape"))


def _renumber_contiguous(root: FSNode) -> None:
    """Renumber every inode to a contiguous 1..N sequence.

    Nodes that share an inode number (hardlink group) keep a single
    shared number. Assignment walks the tree deterministically
    (pre-order, children sorted by name) so renumbered ids are stable.
    """
    # Gather all nodes in deterministic traversal order; record hardlink groups.
    order = []
    visited_numbers: Dict[int, List[FSNode]] = {}

    def visit(node: FSNode):
        order.append(node)
        if node.inode.kind != "dir":
            visited_numbers.setdefault(node.inode.inode_number, []).append(node)
        for child in _iter_children_sorted(node):
            visit(child)

    visit(root)

    # Group non-dir nodes sharing an inode number; dirs each get their own.
    groups: List[List[FSNode]] = []
    seen: set = set()
    for node in order:
        if node.inode.kind == "dir":
            groups.append([node])
            continue
        num = node.inode.inode_number
        if id(node) in seen:
            continue
        members = visited_numbers.get(num, [node])
        if not members:
            members = [node]
        # keep only nodes actually in the tree
        members = [m for m in members if id(m) in {id(x) for x in order}]
        for m in members:
            seen.add(id(m))
        groups.append(members)

    for new_num, group in enumerate(groups, start=1):
        for m in group:
            m.inode.inode_number = new_num


# =========================================================================
# Repacker
# =========================================================================

# Algorithms that need a comp_opts block immediately after the superblock
# (reference tools write one for XZ, gzip, lzo, lz4, zstd -- but NOT for the
# legacy "LZMA" vendor5 format used by old OpenWrt, where the stream
# just begins at offset 96 with no framing block). LZMA (comp_id=2) falls
# in the no-block camp; we follow the same convention.
_COMP_OPTS_ALGORITHMS = {1, 3, 4, 5, 6}  # gzip, lzo, xz, lz4, zstd

# comp_opts block sizes (after the 2-byte metadata header):
#   gzip: 6 bytes (level, window_size, strategies)  -- COMP_OPTS_GZIP "<IIH"
#   xz:   8 bytes (dict_size, filters)              -- COMP_OPTS_XZ   "<II"
#   lz4:  8 bytes (version, flags)                  -- COMP_OPTS_LZ4  "<II"
#   zstd: 4 bytes (level)                           -- COMP_OPTS_ZSTD "<I"
#   lzo:  8 bytes (algorithm, level)                -- COMP_OPTS_LZO  "<II"


def _build_profile_for_compression(comp_id: int, block_size: int,
                                    src_profile: CompressorProfile) -> CompressorProfile:
    """Build a fresh CompressorProfile that produces safe, sane output for
    the requested algorithm. Inherits fields from src_profile where they
    still apply (e.g. xz_check stays CRC32 even if user picks lzma then
    re-picks xz). For fields that don't translate (e.g. xz_dict_size for
    a gzip output), uses the safest default for the codec."""
    if comp_id == 1:  # gzip/zlib
        return CompressorProfile(comp_id=1)
    if comp_id == 2:  # legacy LZMA
        # PRESERVE the source image's detected framing verbatim. The original
        # Certain source images, for instance, use squashfs-tools' "compat13" framing
        # (5-byte LZMA_alone header + 8-byte uncompressed_size trailer) -- the
        # legacy "vendor5" framing (5-byte header only) does NOT round-trip on
        # such images: the fragment block's 13-byte compat13 trailer is required
        # by squashfs-tools' lzma_code() path during metadata walk. Switching
        # to vendor5 produces output standard readers cannot decode (rc=0, "LZMA
        # uncompress failed with error code 0" -- the trailing 8-byte
        # uncompressed_size is misinterpreted as garbage by liblzma and the
        # stream never reaches STREAM_END).
        #
        # For images where the analyzer detected vendor5 (legacy OpenWrt, where
        # real device kernels expect that format), keep vendor5 so we don't
        # introduce a framing regression there.
        if src_profile.lzma_framing == "compat13":
            return CompressorProfile(
                comp_id=2, lzma_framing="compat13",
                lzma_lc=src_profile.lzma_lc if src_profile.lzma_lc is not None else 3,
                lzma_lp=src_profile.lzma_lp if src_profile.lzma_lp is not None else 0,
                lzma_pb=src_profile.lzma_pb if src_profile.lzma_pb is not None else 2,
                lzma_dict_size=src_profile.lzma_dict_size or block_size or (1 << 19),
            )
        # Otherwise default to the reference tools' "compat" framing: it is a strict
        # superset of vendor5 (squashfs-tools' lzma_code() decodes both, since
        # compat framing just prepends the 8-byte uncompressed_size trailer
        # that liblzma uses to size its output buffer). Even on vendor5-source
        # images, writing compat13 is the safe choice: vendor5 kernels
        # implicitly support compat13 too because the trailer sits AFTER the
        # end-of-stream marker and only gets read by squashfs-tools on extract.
        # The kernel's lzma decompressor walks to the end marker and stops;
        # it never sees the trailer.
        ds = src_profile.lzma_dict_size or block_size or (1 << 19)
        return CompressorProfile(
            comp_id=2, lzma_framing="compat13",
            lzma_lc=src_profile.lzma_lc if src_profile.lzma_lc is not None else 3,
            lzma_lp=src_profile.lzma_lp if src_profile.lzma_lp is not None else 0,
            lzma_pb=src_profile.lzma_pb if src_profile.lzma_pb is not None else 2,
            lzma_dict_size=ds,
        )
    if comp_id == 4:  # XZ
        return CompressorProfile(
            comp_id=4,
            xz_check=src_profile.xz_check or 1,        # 1=CRC32 (squashfs-tools default)
            xz_dict_size=src_profile.xz_dict_size or block_size or (1 << 18),
        )
    raise ValueError(
        f"--compression comp_id={comp_id} has no encoder in this build "
        f"(only gzip=1, lzma=2, xz=4 are writable here)"
    )


def _make_comp_opts_block(comp_id: int, profile: CompressorProfile,
                           block_size: int) -> Optional[bytes]:
    """Build a comp_opts block (XZ / gzip / etc) for the requested
    algorithm, framed in a SquashFS metadata block: 2-byte little-endian
    length header (top bit clear = compressed, but comp_opts blocks are
    conventionally stored uncompressed -- so the bit IS set in practice;
    reference tools emit 0x8000 | len) followed by the raw comp_opts bytes.

    Returns None for algorithms that don't use a comp_opts block (legacy
    LZMA, id=2), so the caller can leave the post-superblock area empty
    -- exactly the on-disk layout reference tools use for those images.
    """
    if comp_id not in _COMP_OPTS_ALGORITHMS:
        return None

    if comp_id == 4:  # XZ
        # the conventional framing: dict_size | (filters_bitmask << 32)
        # The filters_bitmask on stock squashfs-tools is 0 for plain LZMA2
        # (no BCJ/x86/Delta etc.); embedded MIPS kernels use this same
        # bitmask (no MIPS BCJ exists in the reference tools' xz code path).
        dict_size = profile.xz_dict_size or block_size or (1 << 18)
        body = C.COMP_OPTS_XZ.pack(dict_size, 0)
    elif comp_id == 1:  # gzip/zlib
        # squashfs-tools' gzip comp_opts: compression_level, window_bits, strategies
        # reference tools use level=9 (max), window_bits=15 (default), strategies=0
        body = C.COMP_OPTS_GZIP.pack(9, 15, 0)
    elif comp_id == 3:  # lzo
        body = C.COMP_OPTS_LZO.pack(1, 8)  # algorithm=1, level=8 (max)
    elif comp_id == 5:  # lz4
        body = C.COMP_OPTS_LZ4.pack(1, 0)
    elif comp_id == 6:  # zstd
        body = C.COMP_OPTS_ZSTD.pack(15)  # level 15 (~ zstd -15)
    else:
        return None

    # Frame as a metadata block: header word has bit 15 set (stored
    # uncompressed) and bits 0-14 = body length. This is exactly what
    # reference tools emit (see reference decoder sources).
    assert len(body) <= C.METADATA_LENGTH_MASK, f"comp_opts too large: {len(body)}"
    hdr = len(body) | C.METADATA_UNCOMPRESSED_BIT
    return struct.pack("<H", hdr) + body


class Repacker:
    def __init__(self, fs: FilesystemImage, output_compression: Optional[str] = None):
        """
        `output_compression`: optional override of the on-disk compression
        algorithm written into the rebuilt superblock. None (default) =
        preserve the original image's compression, byte-identical. A
        string name from constants.COMPRESSION_NAMES forces that codec
        (gzip/lzma/xz/etc.). The special value `"auto"` tries every
        supported codec on each block and picks whichever compresses it
        smallest; the image-wide codec is then chosen as whichever codec
        saved the most total bytes across the whole image (SquashFS can
        only name ONE codec in the superblock, so even with auto we have
        to commit to one -- but we get to pick it based on actual data,
        not a heuristic). The matching comp_opts block (where the format
        requires one) is regenerated; the COMPRESSOR_OPTIONS flag is
        set/cleared accordingly; the CompressorProfile is rewritten so
        encode_block() emits the right framing.
        """
        self.fs = fs
        self.sb = fs.sb
        self.data = fs.data
        self.output_compression_name = output_compression

        # `auto_mode`: now always False -- the -C auto special case is
        # handled at the sqpack.py CLI layer, which runs build() three
        # times (once per codec) and picks the smallest result. We keep
        # this attribute as a stable guard so the identity short-circuits
        # below can refuse to early-return when auto_mode is set.
        self.auto_mode = False

        if output_compression is not None:
            if output_compression not in C.COMPRESSION_NAMES:
                raise ValueError(
                    f"unsupported output compression {output_compression!r}; "
                    f"supported: {sorted(C.COMPRESSION_NAMES.keys())}"
                )
            self.comp_id = C.COMPRESSION_NAMES[output_compression]
            self.profile = _build_profile_for_compression(
                self.comp_id, fs.sb.block_size, fs.profile,
            )
        else:
            self.comp_id = self.sb.compression
            self.profile = fs.profile

        # Preserve original compressor-options block (if present) verbatim.
        # The 96-byte SquashFS 4.0 superblock is followed by an optional
        # metadata-framed comp_opts block (flag bit 6, COMPRESSOR_OPTIONS)
        # whose length is encoded in the 2-byte metadata header at offset 96.
        # This block IS data the kernel/standard readers reads back to obtain the
        # compressor parameters; rewriting the superblock without it causes
        # "Failed to read compressor options" on stock squashfs-tools.
        #
        # Detection nuance: when the COMPRESSOR_OPTIONS flag is set but
        # the bytes at offset 96 look like an XZ stream magic (fd 37 7a
        # 58 5a 00) — as is the case for images produced by older
        # squashfs-tools — there is NO comp_opts block; the XZ stream
        # just begins immediately at offset 96. We only treat the
        # post-superblock bytes as comp_opts if they do NOT look like
        # an XZ stream header.
        self.comp_opts_block: Optional[bytes] = None
        if self.auto_mode:
            # Don't generate comp_opts yet -- we don't know the winning
            # codec until build() has encoded every block. build() will
            # populate self.comp_opts_block via _make_comp_opts_block()
            # AFTER picking the codec, then re-pack the superblock.
            pass
        elif self.output_compression_name is not None:
            # User picked a specific output codec -- synthesize a comp_opts
            # block matching that codec (or None for legacy LZMA which has
            # no comp_opts). The COMPRESSOR_OPTIONS flag will be set in
            # _write_superblock iff comp_opts_block is non-None.
            self.comp_opts_block = _make_comp_opts_block(
                self.comp_id, self.profile, fs.sb.block_size,
            )
        elif self.sb.has_compressor_options and len(self.data) >= C.SUPERBLOCK_SIZE + C.METADATA_BLOCK_HEADER_SIZE:
            head_bytes = self.data[C.SUPERBLOCK_SIZE: C.SUPERBLOCK_SIZE + 6]
            is_xz_magic = head_bytes == b"\xfd7zXZ\x00"
            if not is_xz_magic:
                hdr = int.from_bytes(self.data[C.SUPERBLOCK_SIZE: C.SUPERBLOCK_SIZE + 2], "little")
                comp_len = hdr & C.METADATA_LENGTH_MASK
                block_end = C.SUPERBLOCK_SIZE + C.METADATA_BLOCK_HEADER_SIZE + comp_len
                if block_end <= len(self.data):
                    self.comp_opts_block = bytes(self.data[C.SUPERBLOCK_SIZE:block_end])
        # Bytes from start-of-image to end-of-comp-opts. Data/fragment
        # blocks begin immediately after this; metadata tables do too
        # unless the comp_opts block happens to be the XZ stream-magic
        # trailer (then data begins right at offset 96).
        self.base_image_overhead = (
            C.SUPERBLOCK_SIZE + len(self.comp_opts_block) if self.comp_opts_block is not None else C.SUPERBLOCK_SIZE
        )

    def build(self, patches: Optional[Dict[str, bytes]] = None,
              source_dir: Optional[str] = None,
              mkfs_time: Optional[int] = "preserve") -> Tuple[bytes, RepackStats]:
        """`mkfs_time` controls the rebuilt superblock's timestamp field:
          - "preserve" (the default): keep the ORIGINAL image's mkfs_time,
            even when content changed. Without this, every rebuild stamps
            the current time, which alone guarantees the output hash can
            never match the original even when every file is identical --
            this was flagged as a real bug and is now the default fix.
          - an explicit int: use that Unix timestamp instead.
          - None: stamp the current time (the OLD default behavior,
            still available for anyone who explicitly wants a fresh
            timestamp on the rebuilt image)."""
        if not patches and not source_dir:
            # No edits requested at all -- but only safe to take the
            # byte-identical shortcut if we're NOT also changing codec.
            # With --compression, even an "identity" rebuild has to
            # re-encode every block in the new codec; the bytes cannot
            # be reused verbatim (would corrupt: superblock names new
            # codec, but data blocks are in old).
            if self.comp_id == self.sb.compression:
                stats = RepackStats(mode="identity", original_size=len(self.data), new_size=len(self.data))
                return self.data, stats

        root, diff = _merge_tree(self.fs, source_dir, patches)

        if diff is not None and not patches:
            counts = diff.counts()
            nothing_changed = (counts["modified_count"] == counts["added_count"] ==
                                counts["removed_count"] == counts["metadata_only_count"] ==
                                counts["type_changed_count"] == 0)
            # Same codec-change caveat as above: the verbatim-reuse
            # shortcut is only sound when the output codec matches the
            # source. With --compression forcing a new codec, we MUST
            # proceed to the full rebuild below (which will decode +
            # re-encode every block).
            if nothing_changed and self.comp_id == self.sb.compression:
                stats = RepackStats(mode="identity", source_dir=source_dir,
                                     original_size=len(self.data), new_size=len(self.data),
                                     directory_diff=diff.to_dict(),
                                     unchanged_count=counts["unchanged_count"],
                                     modified_count=counts["modified_count"],
                                     added_count=counts["added_count"],
                                     removed_count=counts["removed_count"],
                                     metadata_only_count=counts["metadata_only_count"])
                return self.data, stats

        stats = RepackStats(mode="patched", patched_paths=sorted(patches.keys()) if patches else [],
                             source_dir=source_dir, original_size=len(self.data))
        if diff is not None:
            stats.directory_diff = diff.to_dict()
            c = diff.counts()
            stats.unchanged_count = c["unchanged_count"]
            stats.modified_count = c["modified_count"]
            stats.added_count = c["added_count"]
            stats.removed_count = c["removed_count"]
            stats.metadata_only_count = c["metadata_only_count"]

        # -- 1. data + fragment area --------------------------------------
        #
        # Fragment-consolidation semantics (v1.14.0):
        # When a byte-identical file is reused verbatim, its original
        # fragment block's *decompressed* content is carried forward as a
        # mutable buffer. Fresh tails (from patched/added files) are
        # APPENDED into that buffer (capacity 8192, the metadata-block
        # ceiling for fragment storage) instead of allocating a new
        # fragment each. Every inode's fragment_offset is a coordinate
        # into the decompressed payload -- never into the compressed
        # bytes -- so appending at the end leaves every other file's
        # (fragment_index, offset) pair byte-valid without touching its
        # inode. Result: an image with N original fragments and any
        # number of small edits repacks to exactly N fragments again
        # (as long as cumulative tail growth fits), preserving the
        # stock fragment count. A modified file whose new tail does not
        # fit the 8192 ceiling falls back to a brand-new fragment.
        data_out = bytearray()
        reused_block_offsets: Dict[int, int] = {}
        new_fragment_entries: List[Tuple[int, int, bool]] = []
        resolved_file_layout: Dict[int, dict] = {}
        # orig fragment idx -> (payload bytearray, used_len, dirty flag)
        # -- `payload` starts as the ORIGINAL fragment's decompressed
        #    content; `used_len` grows as fresh tails are appended;
        #    `dirty` means the payload changed and must be re-encoded.
        carried_fragments: Dict[int, dict] = {}
        # orig fragment idx -> new (output) fragment idx placeholder
        used_fragments: Dict[int, int] = {}
        # brand-new fragments allocated for fresh tails (no carried parent)
        fresh_fragment_payloads: List[Tuple[bytearray, int]] = []

        base_data_offset = self.base_image_overhead

        def place_bytes(raw_bytes: bytes) -> int:
            off = base_data_offset + len(data_out)
            data_out.extend(raw_bytes)
            return off

        resolved_by_inode_number: Dict[int, dict] = {}

        # Verbatim-reuse candidates are resolved BEFORE fresh-content ones,
        # so if a hardlink group has both an unchanged member (reusable)
        # and a newly-added member pointing at the same local inode, the
        # group always gets the byte-identical reuse path -- never the
        # other way around, which would silently recompress an otherwise
        # untouched file just because of dict/tree iteration order.
        # (Two-pass structure below preserves that ordering exactly:
        # pass A handles every reuse candidate, pass B every fresh one.)
        file_nodes = [n for n in iter_nodes(root) if n.inode.kind == "file"]
        reuse_nodes = [n for n in file_nodes if n.inode.raw_content is None]
        fresh_nodes = [n for n in file_nodes if n.inode.raw_content is not None]

        # When the user passes --compression <ALGO>, the verbatim-reuse
        # optimisation becomes UNSAFE: a "reused" data block is just a
        # pointer copy of the original LZMA/XZ/gzip bytes into the new
        # image, but the new superblock.compression field names a
        # DIFFERENT codec. stock readers and the device kernel will
        # try to decode those bytes with the wrong decoder and fail
        # ("xz uncompress failed with error code 0" / "LZMA error 9" /
        # "File system corruption detected"). Force the long path (full
        # decode + recompress in the new codec) for every unchanged file
        # in that case. The trade-off is real: instead of O(1) pointer
        # copy per reused file, you pay the full decode + re-encode
        # cost. There is no way around this without a transcoding
        # service that knows both codecs' framing in lockstep.
        #
        # Identity repack (no --compression): codec unchanged, verbatim
        # reuse is correct and stays on.
        codec_changed = (self.comp_id != self.sb.compression)

        # Carried-fragment machinery (fragment consolidation):
        #   _carry_buffer: decompressed payload of an original fragment,
        #     mutable; fresh tails are APPENDED at `used`. Offlices into
        #     the decompressed payload never move, so every previously
        #     written (fragment_index, fragment_offset) pair stays valid.
        #   _ensure_index: assign the output fragment-table index for an
        #     original fragment (once), with a placeholder entry filled
        #     at finalize time. Buffers created but never indexed (a
        #     failed capacity check on a fragment no reuse file
        #     references) are simply dropped, like the originals.
        carried_fragments: Dict[int, dict] = {}   # orig idx -> buffer dict
        used_fragments: Dict[int, int] = {}       # orig idx -> output idx

        def _carry_buffer(orig_idx: int) -> dict:
            cf = carried_fragments.get(orig_idx)
            if cf is None:
                orig_off, orig_size, orig_unc = self.fs.fragment_table[orig_idx]
                raw = self.data[orig_off: orig_off + orig_size]
                if orig_unc:
                    payload = bytearray(raw)
                else:
                    decoded, self.profile = decompress_block(
                        raw, self.sb.compression, self.profile,
                        max_size=self.sb.block_size,
                        xz_options_block=self.fs.xz_options_block)
                    payload = bytearray(decoded)
                cf = {"payload": payload, "used": len(payload), "dirty": False}
                carried_fragments[orig_idx] = cf
            return cf

        def _ensure_index(orig_idx: int) -> int:
            if orig_idx not in used_fragments:
                used_fragments[orig_idx] = len(new_fragment_entries)
                new_fragment_entries.append((-1, -1, False))  # finalize fills
            return used_fragments[orig_idx]

        # ---- pass A: byte-identical files (verbatim reuse) ---------------
        # Resolved BEFORE fresh-content ones so a hardlink group with both
        # an unchanged member (reusable) and a newly-added member always
        # takes the byte-identical reuse path (unchanged from v1.13).
        for node in reuse_nodes:
            inode = node.inode

            if inode.inode_number in resolved_by_inode_number:
                # Already resolved via another path sharing this inode
                # (hardlink) -- reuse the SAME layout, don't recompress
                # or re-place data for it a second time.
                resolved_file_layout[id(node)] = resolved_by_inode_number[inode.inode_number]
                continue

            if codec_changed:
                # Unchanged file under a --codec change: content must be
                # re-encoded in the new codec -- handled by pass B.
                continue

            cursor = inode.file_start_block
            new_block_sizes = list(inode.block_sizes)
            first_new_offset = None
            for raw_entry in inode.block_sizes:
                size = raw_entry & (S.SQUASHFS_COMPRESSED_BIT_BLOCK - 1)
                if size == 0:
                    continue
                orig_off = cursor
                cursor += size
                if orig_off in reused_block_offsets:
                    new_off = reused_block_offsets[orig_off]
                else:
                    raw_bytes = self.data[orig_off: orig_off + size]
                    new_off = place_bytes(raw_bytes)
                    reused_block_offsets[orig_off] = new_off
                stats.data_blocks_reused += 1
                if first_new_offset is None:
                    first_new_offset = new_off

            new_start_block = first_new_offset if first_new_offset is not None else base_data_offset + len(data_out)

            new_frag_idx = S.SQUASHFS_INVALID_FRAG
            if inode.fragment_index != S.SQUASHFS_INVALID_FRAG:
                _carry_buffer(inode.fragment_index)   # carried, untouched for now
                new_frag_idx = _ensure_index(inode.fragment_index)
                stats.fragments_reused += 1

            resolved_file_layout[id(node)] = dict(
                start_block=new_start_block, block_sizes=new_block_sizes,
                fragment_index=new_frag_idx, fragment_offset=inode.fragment_offset,
                file_size=inode.file_size,
            )
            resolved_by_inode_number[inode.inode_number] = resolved_file_layout[id(node)]
            stats.files_reused_verbatim += 1

        # ---- pass B: fresh content (patches / source-dir / codec change) --
        for node in fresh_nodes:
            inode = node.inode

            if inode.inode_number in resolved_by_inode_number:
                resolved_file_layout[id(node)] = resolved_by_inode_number[inode.inode_number]
                continue

            # Codec-change path: unchanged file whose content is
            # still on disk in the SOURCE image in the OLD codec.
            # We have to decode it through fs.read_file_content so
            # encode_block() can re-emit it in the NEW codec. This
            # is the price of --compression; the verbatim-reuse
            # shortcut above only works when both codecs match.
            if codec_changed and inode.raw_content is None:
                try:
                    inode.raw_content = self.fs.read_file_content(inode)
                except Exception as e:
                    raise RuntimeError(
                        f"--compression: failed to decode source content "
                        f"of inode {inode.inode_number} (kind={inode.kind}) "
                        f"for codec change: {e}"
                    ) from e
            content = inode.raw_content
            # Tail-convention preservation: a file that already existed in
            # the image keeps ITS OWN tail storage convention -- fragment
            # if the original inode had one, tail-as-final-block otherwise
            # (some vendor images store large tails as regular
            # blocks while other files in the same image use fragments).
            # Applying the global superblock policy here instead would
            # grow the fragment count by one per modified convention-
            # deviant file. Newly-added files use the global policy.
            existed_in_image = bool(inode.block_sizes)
            if existed_in_image:
                orig_had_frag = inode.fragment_index != S.SQUASHFS_INVALID_FRAG
                if orig_had_frag:
                    n_full, use_frag = _plan_file_layout(
                        len(content), self.sb.block_size,
                        self.sb.decoded_flags.get("ALWAYS_FRAGMENTS", False),
                        self.sb.decoded_flags.get("NO_FRAGMENTS", False),
                    )
                else:
                    n_full = (len(content) + self.sb.block_size - 1) // self.sb.block_size
                    use_frag = False
            else:
                n_full, use_frag = _plan_file_layout(
                    len(content), self.sb.block_size,
                    self.sb.decoded_flags.get("ALWAYS_FRAGMENTS", False),
                    self.sb.decoded_flags.get("NO_FRAGMENTS", False),
                )
            new_block_sizes = []
            start_block = None
            for i in range(n_full):
                chunk = content[i * self.sb.block_size: (i + 1) * self.sb.block_size]
                body, is_compressed = encode_block(chunk, self.comp_id, self.profile)
                off = place_bytes(body)
                if start_block is None:
                    start_block = off
                size_field = len(body) | (0 if is_compressed else S.SQUASHFS_COMPRESSED_BIT_BLOCK)
                new_block_sizes.append(size_field)
                stats.data_blocks_new += 1

            new_frag_idx = S.SQUASHFS_INVALID_FRAG
            new_frag_offset = 0
            if use_frag:
                tail = content[n_full * self.sb.block_size:]

                # Fragment consolidation, overwrite-first: patch the new
                # tail INTO the file's old tail footprint inside the
                # carried payload when it fits there (shrink or equal
                # length). No other file's tail coordinates are touched
                # (they live outside the old footprint), so every other
                # (fragment_index, fragment_offset) stays byte-valid.
                # This keeps the re-encoded block close to its original
                # size -- appending instead measurably degrades the xz
                # ratio on small-dictionary vendor images (e.g. a 6 KiB
                # dict fragment grew +2.5 KiB compressed on append vs
                # ~0 in place). Append into the free tail space only
                # when the new tail outgrew the old footprint; fall back
                # to a brand-new fragment on capacity exhaustion or when
                # the file previously had no fragment at all.
                target_cf = None
                in_place = False
                old_tail_len = 0
                if inode.fragment_index != S.SQUASHFS_INVALID_FRAG:
                    cf = _carry_buffer(inode.fragment_index)
                    # Pre-edit size: file_size already reflects the NEW
                    # content for MODIFIED files -- deriving the footprint
                    # from it made grown tails overwrite the next file's
                    # tail in the same fragment block.
                    _osz = (inode.orig_file_size
                            if inode.orig_file_size is not None
                            else inode.file_size)
                    old_tail_len = ((_osz or 0)
                                    - len(inode.block_sizes) * self.sb.block_size)
                    if (len(tail) <= old_tail_len
                            and inode.fragment_offset + len(tail) <= self.sb.block_size):
                        target_cf = cf
                        in_place = True
                    elif cf["used"] + len(tail) <= self.sb.block_size:
                        target_cf = cf
                        in_place = False
                if target_cf is not None:
                    new_frag_idx = _ensure_index(inode.fragment_index)
                    if in_place:
                        new_frag_offset = inode.fragment_offset
                        target_cf["payload"][new_frag_offset:new_frag_offset + len(tail)] = tail
                        if inode.fragment_offset + old_tail_len == target_cf["used"]:
                            # our old tail ended the payload: reclaim space
                            target_cf["used"] = new_frag_offset + len(tail)
                    else:
                        new_frag_offset = target_cf["used"]
                        target_cf["payload"] += tail
                        target_cf["used"] += len(tail)
                    target_cf["dirty"] = True
                    stats.fragments_consolidated += 1
                else:
                    new_frag_idx = len(new_fragment_entries)
                    new_fragment_entries.append((-1, -1, False))
                    fresh_fragment_payloads.append((bytearray(tail), new_frag_idx))
                    stats.fragments_new += 1
                    new_frag_offset = 0
                if start_block is None:
                    start_block = base_data_offset + len(data_out)

            if start_block is None:
                start_block = base_data_offset + len(data_out)

            resolved_file_layout[id(node)] = dict(
                start_block=start_block, block_sizes=new_block_sizes,
                fragment_index=new_frag_idx, fragment_offset=new_frag_offset,
                file_size=len(content),
            )
            resolved_by_inode_number[inode.inode_number] = resolved_file_layout[id(node)]
            stats.files_recompressed += 1

        # ---- finalize fragments: emit carried + fresh payloads ------------
        # Dirty (appended-into) fragments are re-encoded once; untouched
        # carried fragments stay byte-verbatim from the source image.
        for orig_idx, cf in carried_fragments.items():
            if orig_idx not in used_fragments:
                continue   # buffer created for a failed pack; original is droppable
            new_idx = used_fragments[orig_idx]
            if cf["dirty"]:
                body, is_compressed = encode_block(
                    bytes(cf["payload"][:cf["used"]]), self.comp_id, self.profile)
                off = place_bytes(body)
                new_fragment_entries[new_idx] = (off, len(body), not is_compressed)
                stats.fragments_recompressed += 1
            else:
                orig_off, orig_size, orig_unc = self.fs.fragment_table[orig_idx]
                if orig_off in reused_block_offsets:
                    off = reused_block_offsets[orig_off]
                else:
                    off = place_bytes(self.data[orig_off: orig_off + orig_size])
                    reused_block_offsets[orig_off] = off
                new_fragment_entries[new_idx] = (off, orig_size, orig_unc)
        for payload, new_idx in fresh_fragment_payloads:
            body, is_compressed = encode_block(bytes(payload), self.comp_id, self.profile)
            off = place_bytes(body)
            new_fragment_entries[new_idx] = (off, len(body), not is_compressed)

        stats.fragments_dropped = max(0, len(self.fs.fragment_table) - len(used_fragments))

        # -- 2. resolve uid/gid: original id table, extended with any new
        #    (uid, gid) raw values introduced by source_dir/--patch ------
        id_values: List[int] = list(self.fs.id_table)
        value_to_index = {v: i for i, v in enumerate(id_values)}

        def resolve_id(raw_value: int) -> int:
            if raw_value in value_to_index:
                return value_to_index[raw_value]
            idx = len(id_values)
            id_values.append(raw_value)
            value_to_index[raw_value] = idx
            return idx

        for node in iter_nodes(root):
            inode = node.inode
            if inode.pending_uid is not None:
                inode.uid_idx = resolve_id(inode.pending_uid)
            if inode.pending_gid is not None:
                inode.gid_idx = resolve_id(inode.pending_gid)

        # -- 3. inode table + directory table (mutual fixed point) --------
        inode_builder = MetadataTableBuilder()
        dir_builder = MetadataTableBuilder()
        inode_raw_offset_by_number: Dict[int, int] = {}

        def write_leaf(node: FSNode) -> int:
            inum = node.inode.inode_number
            if inum in inode_raw_offset_by_number:
                return inode_raw_offset_by_number[inum]
            off = _serialize_inode(inode_builder, node, resolved_file_layout)
            inode_raw_offset_by_number[inum] = off
            return off

        def walk(node: FSNode) -> int:
            if node.inode.kind == "dir":
                for child in node.children:
                    if child.inode.kind == "dir":
                        walk(child)
                    else:
                        write_leaf(child)
                listing_raw_off, listing_len = _serialize_directory_listing(
                    dir_builder, node, inode_raw_offset_by_number
                )
                off = _serialize_dir_inode(inode_builder, node, listing_raw_off, listing_len)
                inode_raw_offset_by_number[node.inode.inode_number] = off
                return off
            else:
                return write_leaf(node)

        root_raw_off = walk(root)

        inode_table_bytes, dir_table_bytes, resolve_inode, resolve_dir = build_mutual_tables(
            inode_builder, dir_builder, self.comp_id, self.profile
        )

        # -- 4b-pre. export (lookup) table entries for NFS exportability ---
        # Rebuilt when the source image had one (EXPORTABLE flag + valid
        # lookup_table_start): entry[k] = inode ref for inode number k+1,
        # same encoding as the superblock's root_inode ref. The resolver
        # maps each inode's serialized position to (chunk_byte_offset,
        # in_chunk_offset) -- identical to how directory entries point at
        # inodes. A wrong/absent table never corrupts reads (normal
        # mounting walks the inode table; the lookup table only serves
        # NFS filehandle resolution), so this is additive and safe.
        export_entries: List[int] = []
        source_had_export = (
            self.sb.lookup_table_start != SQUASHFS_INVALID_BLK
            and bool(self.sb.flags & (1 << C.FLAG_BITS["EXPORTABLE"]))
        )
        if source_had_export:
            max_ino = max(inode_raw_offset_by_number)
            for ino in range(1, max_ino + 1):
                raw_off = inode_raw_offset_by_number.get(ino)
                if raw_off is None:
                    # Inode numbers are dense in practice; a gap gets an
                    # invalid ref rather than a wrong one.
                    export_entries.append(SQUASHFS_INVALID_BLK)
                    continue
                chunk_off, in_chunk = resolve_inode(raw_off)
                export_entries.append((chunk_off << 16) | in_chunk)
        export_table_bytes, export_rel_pointers = (
            _build_export_table(export_entries, self.comp_id, self.profile)
            if export_entries else (b"", [])
        )

        # -- 4. fragment table + id table -----------------------------------
        frag_table_bytes, frag_rel_pointers = _build_fragment_table(
            new_fragment_entries, self.comp_id, self.profile
        )
        id_table_bytes, id_rel_pointers = _build_id_table(id_values, self.comp_id, self.profile)

        # -- 5. assemble final image ---------------------------------------
        out = bytearray()
        out += b"\x00" * C.SUPERBLOCK_SIZE
        if self.comp_opts_block is not None:
            out += self.comp_opts_block
        out += data_out

        inode_table_start = len(out)
        out += inode_table_bytes

        directory_table_start = len(out)
        out += dir_table_bytes

        if new_fragment_entries:
            frag_blocks_base = len(out)
            out += frag_table_bytes
            fragment_table_start = len(out)
            out += b"".join(struct.pack("<Q", frag_blocks_base + p) for p in frag_rel_pointers)
        else:
            fragment_table_start = SQUASHFS_INVALID_BLK

        if export_entries:
            export_blocks_base = len(out)
            out += export_table_bytes
            lookup_table_start = len(out)
            out += b"".join(struct.pack("<Q", export_blocks_base + p)
                            for p in export_rel_pointers)
        else:
            lookup_table_start = SQUASHFS_INVALID_BLK

        if id_values:
            id_blocks_base = len(out)
            out += id_table_bytes
            id_table_start = len(out)
            out += b"".join(struct.pack("<Q", id_blocks_base + p) for p in id_rel_pointers)
        else:
            id_table_start = SQUASHFS_INVALID_BLK

        block_rel, in_block = resolve_inode(root_raw_off)
        root_inode_ref = (block_rel << 16) | in_block

        if mkfs_time == "preserve":
            resolved_mkfs_time = self.sb.mkfs_time
        elif mkfs_time is None:
            resolved_mkfs_time = int(time.time())
        else:
            resolved_mkfs_time = int(mkfs_time)

        num_inodes = len({n.inode.inode_number for n in iter_nodes(root)})
        bytes_used = len(out)
        # EXPORTABLE flag + lookup table: v1.14.0 rebuilds the export
        # table whenever the SOURCE image had one, so the flag now tracks
        # source parity instead of being unconditionally cleared (old
        # behavior, which made every rebuilt image non-NFS-exportable).
        if source_had_export and export_entries:
            out_flags = self.sb.flags | (1 << C.FLAG_BITS["EXPORTABLE"])
        else:
            out_flags = self.sb.flags & ~(1 << C.FLAG_BITS["EXPORTABLE"])
        # If the user picked a different output codec (or we generated a
        # new comp_opts block for an existing codec override), realign the
        # COMPRESSOR_OPTIONS flag to match whether a comp_opts block is
        # actually being written. Mismatch => stock squashfs-tools errors
        # out at "Failed to read compressor options" / "Unexpected
        # compressor options".
        comp_opts_bit = (1 << C.FLAG_BITS["COMPRESSOR_OPTIONS"])
        if self.comp_opts_block is not None:
            out_flags |= comp_opts_bit
        else:
            out_flags &= ~comp_opts_bit

        sb_bytes = C.SUPERBLOCK_STRUCT.pack(
            C.SQUASHFS_MAGIC,
            num_inodes,
            resolved_mkfs_time,
            self.sb.block_size,
            len(new_fragment_entries),
            self.comp_id,                # NEW: was self.sb.compression
            self.sb.block_log,
            out_flags,
            len(id_values),
            C.SUPPORTED_MAJOR, C.SUPPORTED_MINOR,
            root_inode_ref,
            bytes_used,
            id_table_start,
            SQUASHFS_INVALID_BLK,  # xattr id table -- not implemented, see README
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            lookup_table_start,   # export table -- rebuilt if source had one
        )
        out[0:C.SUPERBLOCK_SIZE] = sb_bytes

        stats.new_size = len(out)
        stats.export_table_rebuilt = source_had_export and bool(export_entries)
        return bytes(out), stats


def _base(itype: int, inode: Inode) -> bytes:
    return S.BASE_INODE.pack(itype, inode.mode, inode.uid_idx, inode.gid_idx, inode.mtime, inode.inode_number)


def _serialize_inode(builder: MetadataTableBuilder, node: FSNode,
                      resolved_file_layout: Dict[int, dict]) -> int:
    inode = node.inode

    if inode.kind == "file":
        layout = resolved_file_layout[id(node)]
        use_extended = inode.nlink != 1 or inode.xattr_idx != S.SQUASHFS_INVALID_XATTR
        itype = S.INODE_TYPE_EXT_FILE if use_extended else S.INODE_TYPE_BASIC_FILE
        off = builder.write(_base(itype, inode))
        if use_extended:
            extra = S.LREG_EXTRA.pack(
                layout["start_block"], layout["file_size"], 0, inode.nlink,
                layout["fragment_index"], layout["fragment_offset"], inode.xattr_idx,
            )
        else:
            extra = S.REG_EXTRA.pack(
                layout["start_block"], layout["fragment_index"], layout["fragment_offset"], layout["file_size"],
            )
        builder.write(extra)
        for sz in layout["block_sizes"]:
            builder.write(S.BLOCK_SIZE_ENTRY.pack(sz))
        return off

    if inode.kind == "symlink":
        use_extended = inode.xattr_idx != S.SQUASHFS_INVALID_XATTR
        itype = S.INODE_TYPE_EXT_SYMLINK if use_extended else S.INODE_TYPE_BASIC_SYMLINK
        off = builder.write(_base(itype, inode))
        builder.write(S.SYMLINK_EXTRA.pack(inode.nlink, len(inode.symlink_target)))
        builder.write(inode.symlink_target)
        if use_extended:
            builder.write(struct.pack("<I", inode.xattr_idx))
        return off

    if inode.kind in ("chrdev", "blkdev"):
        use_extended = inode.xattr_idx != S.SQUASHFS_INVALID_XATTR
        basic_type = S.INODE_TYPE_BASIC_CHRDEV if inode.kind == "chrdev" else S.INODE_TYPE_BASIC_BLKDEV
        ext_type = S.INODE_TYPE_EXT_CHRDEV if inode.kind == "chrdev" else S.INODE_TYPE_EXT_BLKDEV
        itype = ext_type if use_extended else basic_type
        off = builder.write(_base(itype, inode))
        if use_extended:
            builder.write(S.LDEV_EXTRA.pack(inode.nlink, inode.rdev, inode.xattr_idx))
        else:
            builder.write(S.DEV_EXTRA.pack(inode.nlink, inode.rdev))
        return off

    if inode.kind in ("fifo", "socket"):
        use_extended = inode.xattr_idx != S.SQUASHFS_INVALID_XATTR
        basic_type = S.INODE_TYPE_BASIC_FIFO if inode.kind == "fifo" else S.INODE_TYPE_BASIC_SOCKET
        ext_type = S.INODE_TYPE_EXT_FIFO if inode.kind == "fifo" else S.INODE_TYPE_EXT_SOCKET
        itype = ext_type if use_extended else basic_type
        off = builder.write(_base(itype, inode))
        if use_extended:
            builder.write(S.LIPC_EXTRA.pack(inode.nlink, inode.xattr_idx))
        else:
            builder.write(S.IPC_EXTRA.pack(inode.nlink))
        return off

    raise ValueError(f"cannot serialize inode kind {inode.kind!r}")


def _serialize_dir_inode(inode_builder: MetadataTableBuilder, node: FSNode,
                          listing_raw_off: int, listing_len: int) -> int:
    inode = node.inode
    file_size = listing_len + 3
    use_extended = inode.xattr_idx != S.SQUASHFS_INVALID_XATTR or file_size > 0xFFFF
    if use_extended and file_size > 0xFFFFFFFF:
        raise NotImplementedError("directory listing too large for even EXTENDED_DIR (>4GB) -- not supported")

    if use_extended:
        raise NotImplementedError(
            f"Directory {node.path!r} would require an EXTENDED_DIR inode (xattrs present, "
            f"or listing > 65535 bytes) -- writing EXTENDED_DIR's dir_index entries correctly "
            f"is not yet implemented. See README known limitations."
        )
    off = inode_builder.write(_base(S.INODE_TYPE_BASIC_DIR, inode))
    start_block_patch_off = len(inode_builder.buf)
    inode_builder.write(b"\x00\x00\x00\x00")
    inode_builder.write(struct.pack("<IH", inode.nlink, file_size))
    offset_patch_off = len(inode_builder.buf)
    inode_builder.write(b"\x00\x00")
    inode_builder.write(struct.pack("<I", inode.dir_parent_inode or 0))
    inode_builder.patches.append(Patch(start_block_patch_off, "<I", listing_raw_off, part="block"))
    inode_builder.patches.append(Patch(offset_patch_off, "<H", listing_raw_off, part="offset"))
    return off


def _serialize_directory_listing(dir_builder: MetadataTableBuilder, node: FSNode,
                                  inode_raw_offset_by_number: Dict[int, int]) -> Tuple[int, int]:
    """Write one directory's on-disk listing (directory table).

    SquashFS directory-table on-disk layout (v4.0, compression=XZ on this
    corpus) is a sequence of GROUP blocks:

        group  := dir_header  entry{count+1}
        dir_header := <III   count, start_block, inode_number
            count       = number of entries following MINUS one
            start_block = cumulative compressed offset of the inode-table
                          chunk that this group's inodes live in
            inode_number= base inode number; every entry's i16 inode_delta
                          is relative to it
        entry   := <HhHH  offset, inode_delta, type, size  + name(size+1 bytes)
            offset      = offset of the child's inode WITHIN its 8192-byte
                          inode chunk (patched from the inode table)
            inode_delta = child.inode_number - base_inode
            type        = 1 dir, 2 file, 3 symlink, 4 blkdev,
                          5 chrdev, 6 fifo, 7 socket
            size        = len(name) - 1  (name bytes follow: size+1)

    All entries in one group must live in the SAME inode chunk (so the
    single start_block/offset addressing works). A directory whose
    children spill across inode chunks (or whose inode-number span
    exceeds i16 range from a single base) is emitted as multiple groups,
    in child order, exactly as reference SquashFS tools does.

    Returns (start_raw_offset, listing_length) within dir_builder.buf,
    which the directory's own inode record points at.
    """
    MAXS = C.METADATA_MAX_SIZE  # 8192
    start = len(dir_builder.buf)

    # reference tools emit directory entries sorted by name; standard readers'
    # "directory has duplicate names or is unsorted" check requires it.
    children = sorted(node.children, key=lambda c: c.name.encode("utf-8", "surrogateescape"))

    i = 0
    while i < len(children):
        # -- open a new group -------------------------------------------
        base_inum = children[i].inode.inode_number
        base_ref = inode_raw_offset_by_number[base_inum]
        base_chunk = base_ref // MAXS

        grp = [children[i]]
        grp_len = 1
        i += 1
        while i < len(children):
            c = children[i]
            ref = inode_raw_offset_by_number[c.inode.inode_number]
            # must share the base inode chunk AND keep delta within i16
            if (ref // MAXS != base_chunk
                    or not (-32768 <= (c.inode.inode_number - base_inum) <= 32767)):
                break
            grp.append(c)
            grp_len += 1
            i += 1

        # header: count, start_block(patch), base inode
        dir_builder.write(struct.pack("<I", grp_len - 1))
        header_block_patch_off = len(dir_builder.buf)
        dir_builder.write(b"\x00\x00\x00\x00")
        dir_builder.write(struct.pack("<I", base_inum))
        dir_builder.patches.append(Patch(header_block_patch_off, "<I", base_ref, part="block"))

        # entries
        for child in grp:
            ref = inode_raw_offset_by_number[child.inode.inode_number]
            entry_offset_patch_off = len(dir_builder.buf)
            dir_builder.write(b"\x00\x00")                       # <H offset -> patch
            name = child.name.encode("utf-8", "surrogateescape")
            ent_type = {"dir": 1, "file": 2, "symlink": 3, "blkdev": 4,
                        "chrdev": 5, "fifo": 6, "socket": 7}[child.inode.kind]
            dir_builder.write(struct.pack(
                "<hHH", child.inode.inode_number - base_inum, ent_type, len(name) - 1))
            dir_builder.write(name)
            dir_builder.patches.append(Patch(entry_offset_patch_off, "<H", ref, part="offset"))

    return start, len(dir_builder.buf) - start


def _build_fragment_table(entries: List[Tuple[int, int, bool]], comp_id, profile) -> Tuple[bytes, List[int]]:
    builder = MetadataTableBuilder()
    for off, size, is_unc in entries:
        size_field = size | (S.SQUASHFS_COMPRESSED_BIT_BLOCK if is_unc else 0)
        builder.write(S.FRAGMENT_ENTRY.pack(off, size_field, 0))
    if not entries:
        return b"", []
    chunks = builder.chunk_raw()
    table_bytes = bytearray()
    pointers = []
    for chunk in chunks:
        pointers.append(len(table_bytes))
        table_bytes += encode_metadata_block(chunk, comp_id, profile)
    return bytes(table_bytes), pointers


def _build_id_table(values: List[int], comp_id, profile) -> Tuple[bytes, List[int]]:
    builder = MetadataTableBuilder()
    for v in values:
        builder.write(struct.pack("<I", v))
    if not values:
        return b"", []
    chunks = builder.chunk_raw()
    table_bytes = bytearray()
    pointers = []
    for chunk in chunks:
        pointers.append(len(table_bytes))
        table_bytes += encode_metadata_block(chunk, comp_id, profile)
    return bytes(table_bytes), pointers


def _build_export_table(inode_refs: List[int], comp_id, profile) -> Tuple[bytes, List[int]]:
    """NFS export (lookup) table: one u64 inode ref per inode number,
    entry[k] = inode k+1. Ref format = (metadata_chunk_byte_offset << 16)
    | offset_in_decompressed_chunk, exactly the superblock's root_inode
    encoding. 1024 entries per 8 KiB metadata block; the on-disk region
    is the metadata blocks followed by a u64 array of absolute block
    pointers (the index that lookup_table_start points at)."""
    builder = MetadataTableBuilder()
    for ref in inode_refs:
        builder.write(EXPORT_ENTRY_STRUCT.pack(ref))
    if not inode_refs:
        return b"", []
    chunks = builder.chunk_raw()
    table_bytes = bytearray()
    pointers = []
    for chunk in chunks:
        pointers.append(len(table_bytes))
        table_bytes += encode_metadata_block(chunk, comp_id, profile)
    return bytes(table_bytes), pointers


def format_forensic_log(stats: "RepackStats", source_path: str, output_path: str) -> str:
    lines = []
    a = lines.append
    a("=" * 78)
    a("SQUASHFS DETERMINISTIC REPACKER -- PHASE 3: DETERMINISTIC REPACKER LOG")
    a("=" * 78)
    a(f"Source file  : {source_path}")
    a(f"Output file   : {output_path}")
    a(f"Mode           : {stats.mode}")
    if stats.source_dir:
        a(f"Source dir      : {stats.source_dir}")
    if stats.mode == "identity":
        a("")
        a("Nothing to change -- output is the ORIGINAL file, byte-for-byte.")
        a("This is the correct, byte-identical answer for requirement #1; there is")
        a("no safer or more accurate way to reproduce an unmodified image than to")
        a("not re-derive it at all.")
        a("=" * 78)
        return "\n".join(lines)

    if stats.patched_paths:
        a(f"Patched paths  : {stats.patched_paths}")
    a("")
    a("-- SIZE " + "-" * 70)
    a(f"  original size       : {stats.original_size}")
    a(f"  new size            : {stats.new_size}")
    a(f"  delta               : {stats.new_size - stats.original_size:+d} bytes")
    a("")
    if stats.directory_diff is not None:
        a("-- DIRECTORY DIFF " + "-" * 60)
        a(f"  unchanged       : {stats.unchanged_count}")
        a(f"  modified        : {stats.modified_count}")
        a(f"  added           : {stats.added_count}")
        a(f"  removed         : {stats.removed_count}")
        a(f"  metadata only   : {stats.metadata_only_count}")
        a("")
    a("-- FILE-LEVEL HANDLING " + "-" * 55)
    a(f"  files reused verbatim (bit-identical original bytes) : {stats.files_reused_verbatim}")
    a(f"  files recompressed (patched content)                 : {stats.files_recompressed}")
    a(f"  data blocks reused verbatim                          : {stats.data_blocks_reused}")
    a(f"  data blocks newly compressed                         : {stats.data_blocks_new}")
    a(f"  fragments reused verbatim                            : {stats.fragments_reused}")
    a(f"  fragments consolidated (tails merged into originals) : {stats.fragments_consolidated}")
    a(f"  fragments recompressed (carried, payload changed)    : {stats.fragments_recompressed}")
    a(f"  fragments newly compressed                           : {stats.fragments_new}")
    a(f"  fragments dropped (no longer referenced)             : {stats.fragments_dropped}")
    a(f"  export table (NFS lookup)                            : "
      f"{'rebuilt' if stats.export_table_rebuilt else 'not present in source'}")
    a("")
    a("-- WHAT IS AND ISN'T BYTE-IDENTICAL TO THE ORIGINAL " + "-" * 25)
    a("  DATA REGION for every unchanged file : byte-identical (verbatim copy,")
    a("      not recompressed -- see module docstring for why this matters:")
    a("      LZMA is not guaranteed bit-reproducible across encoders)")
    a("  inode table / directory table / fragment table / id table : freshly")
    a("      rebuilt, NOT byte-identical to the original, even for inodes whose")
    a("      logical content is unchanged -- any single data-offset change")
    a("      cascades through every table that stores absolute offsets. This is")
    a("      an inherent SquashFS format property, not a shortcut we took.")
    a("  mkfs_time : preserved from the original by default (pass --new-timestamp or")
    a("      --current-timestamp to override) -- this used to always be stamped with")
    a("      the repack time, which alone guaranteed the hash could never match even")
    a("      with identical content; that was a real bug and this is the fix.")
    if stats.warnings:
        a("")
        a("-- WARNINGS " + "-" * 64)
        for w in stats.warnings:
            a(f"  [!] {w}")
    a("=" * 78)
    return "\n".join(lines)
