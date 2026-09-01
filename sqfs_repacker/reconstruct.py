"""
reconstruct.py
===============
Phase 2: Metadata reconstruction.

Walks the full filesystem tree (tree.py), extracts every regular file's
real content to disk, recreates symlinks/hardlinks/devices/fifos/
sockets where the host OS allows it, and writes a JSON manifest
capturing every recoverable attribute for every inode.

Critically, for the extracted tree to be usable as `--source-dir` for
an IDENTITY rebuild (Phase 3, Capability 1) when nothing has changed,
extraction must preserve everything directory_diff.py's fast-path
comparison looks at: mode, mtime, and (where the host allows it)
hardlink topology. Getting any of these wrong makes every file look
"changed" to the diff even when a byte was never touched -- this is
why they're handled explicitly below rather than left to the OS
defaults (which would stamp extraction time as mtime and the umask'd
default as mode).

Device/fifo/socket nodes still can't be created without root (mknod).
Rather than let their absence be silently misread later as "the user
deleted this file", we record exactly which paths were skipped into a
small sidecar file (`.sqpack_meta.json`) inside the extraction
directory -- directory_diff.py reads it back and treats those specific
paths as expected-absent rather than REMOVED. No manifest editing, no
JSON editing, and no extra conversion step is needed by the user: the
extracted tree, exactly as --reconstruct left it, is immediately usable
as --source-dir.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import stat as statmod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import pseudo
from .pseudo import DeviceEntry, SIDECAR_DEVICES_FILENAME, try_mknod
from .tree import FilesystemImage, iter_nodes
from .inode_parser import Inode
from . import inode_structs as S

SIDECAR_FILENAME = ".sqpack_meta.json"


def _sha256_of(path: str) -> str:
    """SHA-256 of a file's bytes (streamed, safe for large images)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ReconstructionReport:
    source_path: str
    extracted_to: Optional[str]
    total_nodes: int
    counts_by_kind: Dict[str, int]
    files_extracted: int
    files_failed: List[dict]
    compressor_profile: dict
    warnings: List[str]
    manifest: dict
    analyzed_at: str
    skipped_special_nodes: List[dict] = field(default_factory=list)
    hardlinks_created: int = 0

    def to_json(self, indent=2) -> str:
        return json.dumps({
            "source_path": self.source_path,
            "extracted_to": self.extracted_to,
            "analyzed_at": self.analyzed_at,
            "total_nodes": self.total_nodes,
            "counts_by_kind": self.counts_by_kind,
            "files_extracted": self.files_extracted,
            "files_failed": self.files_failed,
            "compressor_profile": self.compressor_profile,
            "warnings": self.warnings,
            "manifest": self.manifest,
            "skipped_special_nodes": self.skipped_special_nodes,
            "hardlinks_created": self.hardlinks_created,
        }, indent=indent)


def _set_mtime(path: str, mtime: int, follow_symlinks: bool = True) -> None:
    try:
        os.utime(path, (mtime, mtime), follow_symlinks=follow_symlinks)
    except (OSError, NotImplementedError):
        pass  # best-effort -- some platforms/filesystems don't support lutimes on symlinks


def reconstruct(image_path: str, extract_dir: Optional[str] = None,
                 write_files: bool = True) -> ReconstructionReport:
    fs = FilesystemImage(image_path)
    root = fs.build_tree()

    counts: Dict[str, int] = {}
    files_extracted = 0
    files_failed: List[dict] = []
    warnings: List[str] = []
    skipped_special_nodes: List[dict] = []
    hardlinks_created = 0
    total = 0

    # Track the first path written for each inode_number so later paths
    # sharing that inode_number become real hardlinks (os.link) instead
    # of independent copies -- required for hardlink topology to survive
    # a --reconstruct -> (edit) -> --source-dir round trip.
    path_by_inode_number: Dict[int, str] = {}

    if write_files and extract_dir:
        os.makedirs(extract_dir, exist_ok=True)

    for node in iter_nodes(root):
        total += 1
        counts[node.inode.kind] = counts.get(node.inode.kind, 0) + 1

        if not write_files or not extract_dir:
            continue
        target = os.path.join(extract_dir, node.path.lstrip("/")) if node.path != "/" else extract_dir

        try:
            if node.inode.kind == "dir":
                os.makedirs(target, exist_ok=True)
                os.chmod(target, node.inode.mode & 0o7777)
                _set_mtime(target, node.inode.mtime)

            elif node.inode.kind == "file":
                inum = node.inode.inode_number
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                if inum in path_by_inode_number and node.inode.nlink > 1:
                    try:
                        os.link(path_by_inode_number[inum], target)
                        hardlinks_created += 1
                        files_extracted += 1
                        continue
                    except OSError:
                        pass  # cross-device or unsupported -- fall through to a normal copy
                content = fs.read_file_content(node.inode)
                with open(target, "wb") as f:
                    f.write(content)
                os.chmod(target, node.inode.mode & 0o7777)
                _set_mtime(target, node.inode.mtime)
                actual_hash = hashlib.sha256(content).hexdigest()
                node.inode.__dict__["_extracted_sha256"] = actual_hash
                files_extracted += 1
                path_by_inode_number.setdefault(inum, target)

            elif node.inode.kind == "symlink":
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                link_target = node.inode.symlink_target.decode("utf-8", "surrogateescape")
                if os.path.lexists(target):
                    os.remove(target)
                os.symlink(link_target, target)
                _set_mtime(target, node.inode.mtime, follow_symlinks=False)

            elif node.inode.kind in ("chrdev", "blkdev", "fifo", "socket"):
                # The sqpack-proprietary path is: ALWAYS write a sidecar
                # entry for any node we couldn't materialize as a real
                # filesystem entry. mknod is opportunistic — it succeeds
                # when the user has CAP_MKNOD (root or unprivileged
                # containers with the cap) and silently falls back to
                # the sidecar otherwise. No auto-sudo: the sidecar is
                # the primary mechanism, mknod is just a convenience for
                # the cases where it works.
                target_kind = node.inode.kind
                # Build a DeviceEntry for both the mknod attempt and the
                # sidecar write so they can't drift from each other.
                # uid_idx/gid_idx are positions into the SquashFS id
                # table; resolve them to raw values via FilesystemImage.
                try:
                    uid_val = fs.resolve_id(node.inode.uid_idx)
                    gid_val = fs.resolve_id(node.inode.gid_idx)
                except (IndexError, AttributeError):
                    uid_val = node.inode.uid_idx
                    gid_val = node.inode.gid_idx
                if target_kind in ("chrdev", "blkdev"):
                    rdev = node.inode.rdev
                else:
                    rdev = 0
                entry = DeviceEntry(
                    path=node.path,
                    mode=node.inode.mode & 0o7777,
                    uid=uid_val,
                    gid=gid_val,
                    kind=target_kind,
                    rdev=rdev,
                )
                # Opportunistic mknod first (skipped entirely for sockets).
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                created = False
                if target_kind != "socket":
                    created = try_mknod(entry, target)
                if created:
                    _set_mtime(target, node.inode.mtime)
                else:
                    # Always append to the proprietary sidecar so the
                    # repack side can recover these nodes from disk.
                    if write_files and extract_dir:
                        try:
                            pseudo.append(
                                os.path.join(extract_dir, SIDECAR_DEVICES_FILENAME),
                                entry,
                            )
                        except OSError as e:
                            warnings.append(
                                f"{node.path}: sidecar write failed: {e}"
                            )
                    warnings.append(
                        f"{node.path}: {node.inode.kind} node not created on disk "
                        f"(requires privileged mknod) -- metadata preserved in .sqpack_devices"
                    )
                    skipped_special_nodes.append({
                        "path": node.path,
                        "kind": node.inode.kind,
                        "mode": node.inode.mode & 0o7777,
                        "uid": uid_val,
                        "gid": gid_val,
                        "rdev": rdev,
                    })
        except Exception as e:
            files_failed.append({"path": node.path, "kind": node.inode.kind, "error": str(e)})

    if write_files and extract_dir:
        sidecar = {
            "schema_version": 2,
            "source_image": os.path.abspath(image_path),
            "source_sha256": _sha256_of(image_path),
            "extracted_at": datetime.datetime.utcnow().isoformat() + "Z",
            "skipped_special_nodes": skipped_special_nodes,
        }
        with open(os.path.join(extract_dir, SIDECAR_FILENAME), "w") as f:
            json.dump(sidecar, f, indent=2)

    manifest = root.to_manifest_dict()

    return ReconstructionReport(
        source_path=os.path.abspath(image_path),
        extracted_to=os.path.abspath(extract_dir) if (write_files and extract_dir) else None,
        total_nodes=total,
        counts_by_kind=counts,
        files_extracted=files_extracted,
        files_failed=files_failed,
        compressor_profile=fs.profile.to_dict(),
        warnings=warnings,
        manifest=manifest,
        analyzed_at=datetime.datetime.utcnow().isoformat() + "Z",
        skipped_special_nodes=skipped_special_nodes,
        hardlinks_created=hardlinks_created,
    )


def format_forensic_log(report: ReconstructionReport) -> str:
    lines = []
    a = lines.append
    a("=" * 78)
    a("SQUASHFS DETERMINISTIC REPACKER -- PHASE 2: METADATA RECONSTRUCTION LOG")
    a("=" * 78)
    a(f"Source file        : {report.source_path}")
    a(f"Extracted to        : {report.extracted_to or '(not written to disk -- manifest only)'}")
    a(f"Analyzed at (UTC)   : {report.analyzed_at}")
    a("")
    a("-- COMPRESSOR PROFILE (auto-detected) " + "-" * 38)
    for k, v in report.compressor_profile.items():
        a(f"  {k} = {v}")
    a("")
    a("-- TREE SUMMARY " + "-" * 60)
    a(f"  total nodes         : {report.total_nodes}")
    for kind, n in sorted(report.counts_by_kind.items()):
        a(f"      {kind:<10}: {n}")
    a(f"  files extracted     : {report.files_extracted}")
    a(f"  hardlinks created   : {report.hardlinks_created}")
    a(f"  files FAILED        : {len(report.files_failed)}")
    for f in report.files_failed:
        a(f"      [!] {f['path']} ({f['kind']}): {f['error']}")
    a("")
    if report.warnings:
        a("-- WARNINGS " + "-" * 64)
        for w in report.warnings:
            a(f"  [!] {w}")
        a("")
    a("=" * 78)
    return "\n".join(lines)
