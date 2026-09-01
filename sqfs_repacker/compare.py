"""
compare.py
===========
Phase 4: Validation / comparison.

Takes two SquashFS images (typically: an original, and something this
tool's Phase 3 repacker produced from it) and produces a structured,
multi-level diff:

  1. whole-file size + SHA-256
  2. superblock field-by-field diff
  3. region/table layout diff (reuses layout.py's region map from Phase 1
     directly -- same function, same region names, run against both files)
  4. fragment table diff, by CONTENT (decompressed bytes), not by index --
     because Phase 3's repacker can legitimately renumber/drop fragments
     while keeping their content identical, a naive "compare entry N to
     entry N" comparison would misreport dropped/reused fragments as
     changed. Comparing by content hash gets the right answer regardless
     of reindexing.
  5. full filesystem tree diff (reuses tree.py's parser on both images):
     added/removed/changed files, permission/ownership/timestamp diffs,
     and directory listing ORDER diffs -- with changed-file detection
     based on actual extracted content hashes, not just metadata.

This module deliberately does NOT assume the two images came from this
tool's own Phase 3 -- it works on any two SquashFS 4.x images, which is
what makes it a real "compare tool" rather than a self-test harness.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import constants as C
from .superblock import parse_superblock
from .layout import build_layout, Region
from .tree import FilesystemImage, FSNode, iter_nodes
from .compressor import decompress_block, CompressorProfile


@dataclass
class ComparisonReport:
    original_path: str
    rebuilt_path: str
    analyzed_at: str

    original_size: int
    rebuilt_size: int
    original_sha256: str
    rebuilt_sha256: str
    whole_file_identical: bool

    superblock_diff: Dict[str, dict]
    region_diff: Dict[str, dict]
    regions_only_in_original: List[str]
    regions_only_in_rebuilt: List[str]

    fragment_diff: dict
    tree_diff: dict

    summary: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original_path": self.original_path,
            "rebuilt_path": self.rebuilt_path,
            "analyzed_at": self.analyzed_at,
            "whole_file": {
                "original_size": self.original_size,
                "rebuilt_size": self.rebuilt_size,
                "size_delta": self.rebuilt_size - self.original_size,
                "original_sha256": self.original_sha256,
                "rebuilt_sha256": self.rebuilt_sha256,
                "identical": self.whole_file_identical,
            },
            "superblock_diff": self.superblock_diff,
            "region_diff": self.region_diff,
            "regions_only_in_original": self.regions_only_in_original,
            "regions_only_in_rebuilt": self.regions_only_in_rebuilt,
            "fragment_diff": self.fragment_diff,
            "tree_diff": self.tree_diff,
            "summary": self.summary,
        }

    def to_json(self, indent=2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _diff_superblocks(sb_a, sb_b) -> Dict[str, dict]:
    fields = [
        "s_magic", "inodes", "mkfs_time", "block_size", "fragments",
        "compression", "block_log", "flags", "no_ids", "s_major", "s_minor",
        "root_inode", "bytes_used", "id_table_start", "xattr_id_table_start",
        "inode_table_start", "directory_table_start", "fragment_table_start",
        "lookup_table_start",
    ]
    out = {}
    for f in fields:
        va, vb = getattr(sb_a, f), getattr(sb_b, f)
        out[f] = {"original": va, "rebuilt": vb, "same": va == vb}
    return out


def _diff_regions(regions_a: List[Region], regions_b: List[Region]) -> Tuple[dict, List[str], List[str]]:
    by_name_a = {r.name: r for r in regions_a}
    by_name_b = {r.name: r for r in regions_b}
    only_a = sorted(set(by_name_a) - set(by_name_b))
    only_b = sorted(set(by_name_b) - set(by_name_a))
    common = sorted(set(by_name_a) & set(by_name_b))
    out = {}
    for name in common:
        ra, rb = by_name_a[name], by_name_b[name]
        out[name] = {
            "original": {"start": ra.start, "end": ra.end, "size": ra.size, "sha256": ra.sha256},
            "rebuilt": {"start": rb.start, "end": rb.end, "size": rb.size, "sha256": rb.sha256},
            "size_delta": rb.size - ra.size,
            "content_identical": ra.sha256 == rb.sha256,
        }
    return out, only_a, only_b


def _fragment_content_hashes(fs: FilesystemImage) -> Dict[str, int]:
    """Returns {sha256_of_decompressed_content: count} across all fragments
    in this image -- a multiset, since duplicate fragment content is
    legitimate (though unusual) and we want counts to match too."""
    hashes: Dict[str, int] = {}
    profile = fs.profile
    xz_opts = getattr(fs, 'xz_options_block', None)
    for off, size, is_unc in fs.fragment_table:
        chunk = fs.data[off: off + size]
        if is_unc:
            content = chunk
        else:
            content, profile = decompress_block(chunk, fs.sb.compression, profile, max_size=fs.sb.block_size,
                                                xz_options_block=xz_opts)
        h = hashlib.sha256(content).hexdigest()
        hashes[h] = hashes.get(h, 0) + 1
    return hashes


def _diff_fragments(fs_a: FilesystemImage, fs_b: FilesystemImage) -> dict:
    hashes_a = _fragment_content_hashes(fs_a)
    hashes_b = _fragment_content_hashes(fs_b)
    all_hashes = set(hashes_a) | set(hashes_b)
    dropped, added, kept = [], [], 0
    for h in all_hashes:
        ca, cb = hashes_a.get(h, 0), hashes_b.get(h, 0)
        if ca and cb:
            kept += min(ca, cb)
        if ca > cb:
            dropped.append({"sha256": h, "count_removed": ca - cb})
        if cb > ca:
            added.append({"sha256": h, "count_added": cb - ca})
    return {
        "original_fragment_count": len(fs_a.fragment_table),
        "rebuilt_fragment_count": len(fs_b.fragment_table),
        "content_kept": kept,
        "content_dropped": dropped,
        "content_added": added,
    }


def _index_tree(root: FSNode) -> Dict[str, FSNode]:
    return {n.path: n for n in iter_nodes(root)}


def _diff_tree(fs_a: FilesystemImage, fs_b: FilesystemImage) -> dict:
    root_a = fs_a.build_tree()
    root_b = fs_b.build_tree()
    idx_a = _index_tree(root_a)
    idx_b = _index_tree(root_b)

    paths_a, paths_b = set(idx_a), set(idx_b)
    removed = sorted(paths_a - paths_b)
    added = sorted(paths_b - paths_a)
    common = sorted(paths_a & paths_b)

    changed_content: List[dict] = []
    changed_metadata: List[dict] = []
    unchanged = 0

    for path in common:
        na, nb = idx_a[path], idx_b[path]
        ia, ib = na.inode, nb.inode
        meta_diffs = {}
        for attr in ("mode", "uid_idx", "gid_idx", "mtime"):
            va, vb = getattr(ia, attr), getattr(ib, attr)
            if va != vb:
                meta_diffs[attr] = {"original": va, "rebuilt": vb}
        if ia.kind != ib.kind:
            meta_diffs["kind"] = {"original": ia.kind, "rebuilt": ib.kind}

        content_changed = False
        if ia.kind == "file" and ib.kind == "file":
            if ia.file_size != ib.file_size:
                content_changed = True
            else:
                ca = fs_a.read_file_content(ia)
                cb = fs_b.read_file_content(ib)
                content_changed = (ca != cb)
        elif ia.kind == "symlink" and ib.kind == "symlink":
            content_changed = ia.symlink_target != ib.symlink_target

        if content_changed:
            changed_content.append({"path": path, "kind": ib.kind})
        if meta_diffs:
            changed_metadata.append({"path": path, "diffs": meta_diffs})
        if not content_changed and not meta_diffs:
            unchanged += 1

    # directory listing ORDER diff (only for directories present on both sides)
    order_diffs = []
    for path in common:
        na, nb = idx_a[path], idx_b[path]
        if na.inode.kind != "dir" or nb.inode.kind != "dir":
            continue
        names_a = [c.name for c in na.children]
        names_b = [c.name for c in nb.children]
        if names_a != names_b and sorted(names_a) == sorted(names_b):
            order_diffs.append({"path": path, "original_order": names_a, "rebuilt_order": names_b})

    return {
        "total_original": len(paths_a),
        "total_rebuilt": len(paths_b),
        "unchanged": unchanged,
        "added": added,
        "removed": removed,
        "content_changed": changed_content,
        "metadata_changed": changed_metadata,
        "directory_order_changed": order_diffs,
    }


def compare(original_path: str, rebuilt_path: str) -> ComparisonReport:
    with open(original_path, "rb") as f:
        data_a = f.read()
    with open(rebuilt_path, "rb") as f:
        data_b = f.read()

    sha_a, sha_b = hashlib.sha256(data_a).hexdigest(), hashlib.sha256(data_b).hexdigest()
    whole_identical = data_a == data_b

    sb_a = parse_superblock(data_a)
    sb_b = parse_superblock(data_b)
    sb_a.file_size_on_disk = len(data_a)
    sb_b.file_size_on_disk = len(data_b)

    regions_a = build_layout(sb_a, data_a)
    regions_b = build_layout(sb_b, data_b)
    region_diff, only_a, only_b = _diff_regions(regions_a, regions_b)

    superblock_diff = _diff_superblocks(sb_a, sb_b)

    fs_a = FilesystemImage(original_path)
    fs_b = FilesystemImage(rebuilt_path)
    fragment_diff = _diff_fragments(fs_a, fs_b)
    tree_diff = _diff_tree(fs_a, fs_b)

    summary = []
    if whole_identical:
        summary.append("Files are BYTE-IDENTICAL (whole-file SHA-256 match).")
    else:
        summary.append(
            f"Files differ at the byte level (expected unless this was an identity repack): "
            f"{len(data_a)} -> {len(data_b)} bytes ({len(data_b) - len(data_a):+d})."
        )
    if tree_diff["content_changed"]:
        summary.append(
            f"{len(tree_diff['content_changed'])} file(s) with changed CONTENT: "
            + ", ".join(d["path"] for d in tree_diff["content_changed"])
        )
    else:
        summary.append("No files have changed content.")
    if tree_diff["added"] or tree_diff["removed"]:
        summary.append(f"{len(tree_diff['added'])} added, {len(tree_diff['removed'])} removed.")
    summary.append(
        f"{tree_diff['unchanged']} of {tree_diff['total_original']} filesystem entries are "
        f"completely unchanged (metadata AND content)."
    )
    if fragment_diff["content_dropped"]:
        summary.append(f"{len(fragment_diff['content_dropped'])} fragment content-group(s) dropped (no longer referenced).")
    metadata_region_changed = [
        n for n in ("inode_table", "directory_table", "fragment_table_index", "id_table_index")
        if n in region_diff and not region_diff[n]["content_identical"]
    ]
    data_region_changed = "data_and_fragment_blocks" in region_diff and not region_diff["data_and_fragment_blocks"]["content_identical"]
    summary.append(
        f"data_and_fragment_blocks region {'differs' if data_region_changed else 'is byte-identical'}; "
        f"metadata regions changed: {metadata_region_changed or '(none)'}."
    )

    return ComparisonReport(
        original_path=original_path, rebuilt_path=rebuilt_path,
        analyzed_at=datetime.datetime.utcnow().isoformat() + "Z",
        original_size=len(data_a), rebuilt_size=len(data_b),
        original_sha256=sha_a, rebuilt_sha256=sha_b,
        whole_file_identical=whole_identical,
        superblock_diff=superblock_diff,
        region_diff=region_diff,
        regions_only_in_original=only_a, regions_only_in_rebuilt=only_b,
        fragment_diff=fragment_diff, tree_diff=tree_diff,
        summary=summary,
    )


def format_forensic_log(report: ComparisonReport) -> str:
    lines = []
    a = lines.append
    a("=" * 78)
    a("SQUASHFS DETERMINISTIC REPACKER -- PHASE 4: VALIDATION / COMPARISON LOG")
    a("=" * 78)
    a(f"Original : {report.original_path}")
    a(f"Rebuilt  : {report.rebuilt_path}")
    a(f"Analyzed at (UTC) : {report.analyzed_at}")
    a("")
    a("-- SUMMARY " + "-" * 66)
    for s in report.summary:
        a(f"  * {s}")
    a("")
    a("-- WHOLE FILE " + "-" * 63)
    a(f"  original size : {report.original_size}")
    a(f"  rebuilt size  : {report.rebuilt_size}  (delta {report.rebuilt_size - report.original_size:+d})")
    a(f"  original sha256 : {report.original_sha256}")
    a(f"  rebuilt sha256  : {report.rebuilt_sha256}")
    a(f"  identical        : {report.whole_file_identical}")
    a("")
    a("-- SUPERBLOCK FIELD DIFF " + "-" * 52)
    for field_name, d in report.superblock_diff.items():
        marker = "  " if d["same"] else "[!]"
        a(f"  {marker} {field_name:<24}: original={d['original']!r:<20} rebuilt={d['rebuilt']!r}")
    a("")
    a("-- REGION / TABLE LAYOUT DIFF " + "-" * 47)
    a(f"  {'region':<26}{'orig size':>10}{'new size':>10}{'delta':>8}  identical?")
    for name, d in report.region_diff.items():
        a(f"  {name:<26}{d['original']['size']:>10}{d['rebuilt']['size']:>10}"
          f"{d['size_delta']:>+8}  {d['content_identical']}")
    if report.regions_only_in_original:
        a(f"  only in original: {report.regions_only_in_original}")
    if report.regions_only_in_rebuilt:
        a(f"  only in rebuilt : {report.regions_only_in_rebuilt}")
    a("")
    a("-- FRAGMENT TABLE DIFF (by content, not index) " + "-" * 29)
    fd = report.fragment_diff
    a(f"  original fragment count : {fd['original_fragment_count']}")
    a(f"  rebuilt fragment count  : {fd['rebuilt_fragment_count']}")
    a(f"  content kept            : {fd['content_kept']}")
    for d in fd["content_dropped"]:
        a(f"  [!] dropped content {d['sha256'][:16]}... x{d['count_removed']}")
    for d in fd["content_added"]:
        a(f"  [+] added content   {d['sha256'][:16]}... x{d['count_added']}")
    a("")
    a("-- FILESYSTEM TREE DIFF " + "-" * 53)
    td = report.tree_diff
    a(f"  total entries: original={td['total_original']} rebuilt={td['total_rebuilt']}")
    a(f"  unchanged (metadata AND content): {td['unchanged']}")
    if td["added"]:
        a(f"  added   : {td['added']}")
    if td["removed"]:
        a(f"  removed : {td['removed']}")
    if td["content_changed"]:
        a("  content changed:")
        for d in td["content_changed"]:
            a(f"      [!] {d['path']} ({d['kind']})")
    if td["metadata_changed"]:
        a("  metadata changed (permissions/ownership/mtime/type):")
        for d in td["metadata_changed"]:
            a(f"      [!] {d['path']}: {d['diffs']}")
    if td["directory_order_changed"]:
        a("  directory listing order changed:")
        for d in td["directory_order_changed"]:
            a(f"      [!] {d['path']}")
    a("=" * 78)
    return "\n".join(lines)
