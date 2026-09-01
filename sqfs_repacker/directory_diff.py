"""
directory_diff.py
==================
Computes the difference between the ORIGINAL image's filesystem tree
and an extracted/modified directory tree on disk (--source-dir). This
module does ONLY comparison -- it never touches the output image, never
compresses anything, and never writes a single byte. Its output
(`DirectoryDiff`) is consumed by repacker.py's shared build() pipeline,
which is the ONLY place that actually rebuilds an image -- whether the
patches came from `--patch` or from `--source-dir`, they funnel through
the exact same rebuild engine.

Classification, per path, is one of:
    UNCHANGED       -- exists both sides, content AND metadata identical
    METADATA_ONLY   -- exists both sides, content identical, metadata differs
                       (mode, uid, gid, mtime, symlink target, device
                       major/minor -- any of these alone forces a rebuild
                       of that inode's record, even with identical content)
    MODIFIED        -- exists both sides, content differs
    ADDED           -- exists only in source-dir
    REMOVED         -- exists only in the original image
    TYPE_CHANGED    -- exists both sides, but the inode TYPE differs
                       (e.g. was a regular file, is now a symlink)

Performance: comparison uses a fast path first (size + mtime + mode +
type, no hashing) and only falls back to hashing file content when the
fast path is ambiguous about whether content actually changed (see
`_classify_file`) -- this is what makes it viable on filesystems with
hundreds of thousands of files, per the requirement.
"""

from __future__ import annotations

import hashlib
import os
import stat as statmod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .tree import FilesystemImage, FSNode, iter_nodes
from .inode_parser import Inode
from . import pseudo
from .pseudo import DeviceEntry, SIDECAR_DEVICES_FILENAME as _DEVICES_FILENAME
from . import inode_structs as S

_SIDECAR_FILENAME = ".sqpack_meta.json"


class DirectoryDiffError(ValueError):
    """Raised by resolve_source_image() when source image cannot be located."""


def _load_sidecar(source_dir: str) -> Optional[Dict]:
    """Load .sqpack_meta.json from source_dir, or return None if absent/invalid.

    Forward-compatible: accepts any schema_version, returns the parsed dict
    so callers can check schema_version themselves if they need stricter
    semantics. Returns None (not raises) for missing/malformed files so
    callers can fall back gracefully.
    """
    sidecar_path = os.path.join(source_dir, _SIDECAR_FILENAME)
    if not os.path.isfile(sidecar_path):
        return None
    try:
        import json
        with open(sidecar_path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (OSError, ValueError):
        return None


def resolve_source_image(dir_path: str, explicit_source: Optional[str] = None) -> str:
    """Determine which SquashFS image a reconstructed directory came from.

    Lookup order:
      1. explicit_source (from -s/--source CLI flag) -- must exist as a file
      2. .sqpack_meta.json sidecar's source_image field (schema v2+)
      3. Sibling scan: <dir>.squashfs, <dir>.img, squashfs, squashfs.squashfs
      4. raise DirectoryDiffError with a hint

    Returns absolute path to source image.
    """
    import warnings
    dir_abs = os.path.abspath(dir_path)

    # 1. Explicit source (always wins)
    if explicit_source:
        if not os.path.isfile(explicit_source):
            raise DirectoryDiffError(
                f"--source image does not exist: {explicit_source!r}"
            )
        return os.path.abspath(explicit_source)

    # 2. Sidecar (schema v2+ records source_image)
    sidecar = _load_sidecar(dir_abs)
    if sidecar and sidecar.get("source_image"):
        candidate = sidecar["source_image"]
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
        warnings.warn(
            f"sidecar source_image not found: {candidate!r}; falling back to sibling scan"
        )

    # 3. Sibling scan -- try most-likely names first
    parent = os.path.dirname(dir_abs)
    base = os.path.basename(dir_abs)
    candidates = [
        os.path.join(parent, base + ".squashfs"),
        os.path.join(parent, base + ".img"),
        os.path.join(parent, "squashfs"),
        os.path.join(parent, "squashfs.squashfs"),
        os.path.join(parent, base),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)

    raise DirectoryDiffError(
        f"cannot auto-detect source image for {dir_path!r}. "
        f"Pass -s/--source IMAGE explicitly, or extract the directory "
        f"with sqpack --reconstruct (writes source_image into sidecar)."
    )


class Status(str, Enum):
    UNCHANGED = "UNCHANGED"
    METADATA_ONLY = "METADATA_ONLY"
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    TYPE_CHANGED = "TYPE_CHANGED"


_KIND_BY_STMODE = {
    statmod.S_IFDIR: "dir", statmod.S_IFREG: "file", statmod.S_IFLNK: "symlink",
    statmod.S_IFCHR: "chrdev", statmod.S_IFBLK: "blkdev",
    statmod.S_IFIFO: "fifo", statmod.S_IFSOCK: "socket",
}


@dataclass
class DiffEntry:
    path: str
    name: str
    status: Status
    kind: str                                   # final kind (post-change)
    original_inode: Optional[Inode] = None       # set for UNCHANGED/METADATA_ONLY/MODIFIED/TYPE_CHANGED/REMOVED
    local_path: Optional[str] = None             # set for anything with a source-dir counterpart
    local_stat: Optional[os.stat_result] = None
    metadata_changes: Dict[str, tuple] = field(default_factory=dict)  # field -> (original, new)
    # For ADDED entries coming from .sqpack_devices (the sidecar path --
    # the device couldn't have existed in source-dir because mknod requires
    # root), this carries the full DeviceEntry (mode, uid, gid, rdev) so the
    # repacker can construct the correct synthetic inode.
    device_meta: Optional["DeviceEntry"] = None


@dataclass
class DirectoryDiff:
    """Structured comparison result. Purely descriptive -- see module
    docstring. `entries` covers every path that should exist in the
    FINAL tree (unchanged/metadata_only/modified/added/type_changed),
    keyed by image path, in a form repacker.py can walk directly to
    reconstruct the target hierarchy (parent paths are always present
    before their children, since we build them that way)."""
    entries: Dict[str, DiffEntry] = field(default_factory=dict)

    unchanged_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    removed_files: List[str] = field(default_factory=list)
    changed_symlinks: List[str] = field(default_factory=list)
    changed_devices: List[str] = field(default_factory=list)
    changed_fifos: List[str] = field(default_factory=list)
    changed_sockets: List[str] = field(default_factory=list)
    changed_directories: List[str] = field(default_factory=list)
    metadata_only_changes: List[str] = field(default_factory=list)
    type_changed: List[str] = field(default_factory=list)
    removed_paths_all_kinds: List[str] = field(default_factory=list)  # includes dirs/symlinks/etc, not just files

    def counts(self) -> dict:
        by_status: Dict[str, int] = {}
        for entry in self.entries.values():
            by_status[entry.status.value] = by_status.get(entry.status.value, 0) + 1
        return {
            "unchanged_count": by_status.get(Status.UNCHANGED.value, 0),
            "modified_count": by_status.get(Status.MODIFIED.value, 0),
            "added_count": by_status.get(Status.ADDED.value, 0),
            "removed_count": len(self.removed_paths_all_kinds),
            "metadata_only_count": by_status.get(Status.METADATA_ONLY.value, 0),
            "type_changed_count": by_status.get(Status.TYPE_CHANGED.value, 0),
        }

    def to_dict(self) -> dict:
        d = self.counts()
        d.update({
            "unchanged_files": self.unchanged_files,
            "modified_files": self.modified_files,
            "added_files": self.added_files,
            "removed_files": self.removed_paths_all_kinds,
            "changed_symlinks": self.changed_symlinks,
            "changed_devices": self.changed_devices,
            "changed_fifos": self.changed_fifos,
            "changed_sockets": self.changed_sockets,
            "changed_directories": self.changed_directories,
            "metadata_only_changes": self.metadata_only_changes,
            "type_changed": self.type_changed,
            "entries_detail": {
                path: {"status": e.status.value, "kind": e.kind,
                       "metadata_changes": {k: [str(a), str(b)] for k, (a, b) in e.metadata_changes.items()}}
                for path, e in self.entries.items() if e.status != Status.UNCHANGED
            },
        })
        return d


def _resolve_uid_gid(fs: FilesystemImage, inode: Inode):
    return fs.resolve_uid_gid(inode)


_SPECIAL_KINDS = ("chrdev", "blkdev", "fifo", "socket")


def _scan_uniform_uid_gid(source_dir: str):
    """Returns the single (uid, gid) pair if EVERY path in source_dir
    shares exactly one (uid, gid) pair; None if there's more than one
    distinct pair (bails as soon as a second distinct pair is seen, so
    a genuinely heterogeneous tree costs almost nothing extra) or none
    could be stat'd at all."""
    seen = set()
    try:
        st = os.lstat(source_dir)
        seen.add((st.st_uid, st.st_gid))
    except OSError:
        pass
    for dirpath, dirnames, filenames in os.walk(source_dir, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            seen.add((st.st_uid, st.st_gid))
            if len(seen) > 1:
                return None
    return next(iter(seen)) if seen else None


class _SyntheticStat:
    """Stand-in for os.stat_result for ADDED sidecar entries. Implements
    only the attributes downstream code (st_mode, st_uid, st_gid, st_rdev,
    st_mtime, st_dev, st_ino) actually reads.

    We avoid the real os.stat_result here because its constructor doesn't
    accept st_rdev via positional args on older Pythons, and the only
    call sites that touch it do attribute access -- there's no
    behavioural contract beyond those attribute reads.
    """
    __slots__ = (
        "st_mode", "st_uid", "st_gid", "st_rdev", "st_mtime",
        "st_dev", "st_ino",
    )
    def __init__(self, mode, uid, gid, rdev, mtime=0, dev=0, ino=0):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_rdev = rdev
        self.st_mtime = mtime
        self.st_dev = dev
        self.st_ino = ino


def _synth_stat_for_device(dentry: "DeviceEntry") -> "os.stat_result":
    """Build a synthetic stat for an ADDED special inode that came from
    the .sqpack_devices sidecar. Nothing actually exists on disk at this
    path -- we synthesize the stat purely so the existing
    _apply_entry_in_place / _fresh_inode_from_local machinery can flow
    without special-casing sidecar entries downstream.

    Fields populated:
      st_mode: file-type bits OR'd with permission bits
      st_uid / st_gid: from the sidecar entry
      st_rdev: encoded major|minor for device nodes; 0 for fifo/socket
    """
    if dentry.kind == "chrdev":
        st_mode = statmod.S_IFCHR | (dentry.mode & 0o7777)
    elif dentry.kind == "blkdev":
        st_mode = statmod.S_IFBLK | (dentry.mode & 0o7777)
    elif dentry.kind == "fifo":
        st_mode = statmod.S_IFIFO | (dentry.mode & 0o7777)
    else:  # socket
        st_mode = statmod.S_IFSOCK | (dentry.mode & 0o7777)
    return _SyntheticStat(
        mode=st_mode,
        uid=dentry.uid,
        gid=dentry.gid,
        rdev=dentry.rdev,
    )


def _hash_local_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_original_file(fs: FilesystemImage, inode: Inode) -> str:
    return hashlib.sha256(fs.read_file_content(inode)).hexdigest()


def _classify_file(fs: FilesystemImage, path: str, orig: Inode, st: os.stat_result,
                    local_path: str, suppress_uid_gid: bool = False) -> DiffEntry:
    """Fast path first: if size OR mtime OR mode differ, we know SOMETHING
    changed without hashing (a size mismatch alone proves content differs;
    a size match with mtime/mode mismatch needs a hash to tell content
    changes apart from metadata-only touches). If size, mtime, AND mode
    all match, we trust that as UNCHANGED without hashing at all -- the
    standard rsync-style quick check, needed to stay fast at scale.

    `suppress_uid_gid`: when True (the whole tree was detected as having
    uniform ownership that doesn't match the original -- see
    `_scan_uniform_uid_gid` and its caller), uid/gid differences are
    never reported as changes. This is what makes a non-root extraction
    (unsquashfs OR --reconstruct, files owned by the extracting user
    instead of the image's real uid/gid) compare as UNCHANGED instead of
    669 spurious METADATA_ONLY entries -- the on-disk ownership is an
    artifact of HOW the tree was extracted, not something the user
    changed, and the repacker always uses the ORIGINAL image's uid/gid
    for reused content regardless."""
    orig_uid, orig_gid = _resolve_uid_gid(fs, orig)
    local_mode = statmod.S_IMODE(st.st_mode)
    orig_mode = orig.mode & 0o7777
    local_mtime = int(st.st_mtime)
    size_same = (st.st_size == orig.file_size)
    mtime_same = (local_mtime == orig.mtime)
    mode_same = (local_mode == orig_mode)
    uid_same = suppress_uid_gid or (orig_uid is None or st.st_uid == orig_uid)
    gid_same = suppress_uid_gid or (orig_gid is None or st.st_gid == orig_gid)

    metadata_changes = {}
    if not mode_same:
        metadata_changes["mode"] = (oct(orig_mode), oct(local_mode))
    if not uid_same:
        metadata_changes["uid"] = (orig_uid, st.st_uid)
    if not gid_same:
        metadata_changes["gid"] = (orig_gid, st.st_gid)
    if not mtime_same:
        metadata_changes["mtime"] = (orig.mtime, local_mtime)

    if size_same and mtime_same:
        # Fast path: trust size+mtime match as proof content is unchanged.
        content_changed = False
    else:
        # Ambiguous -- confirm with an actual content hash rather than
        # assuming. A size mismatch alone technically already proves a
        # change, but hashing both here keeps the logic in one place and
        # the cost is one read of a file we already know changed size.
        content_changed = _hash_original_file(fs, orig) != _hash_local_file(local_path)

    if content_changed:
        status = Status.MODIFIED
    elif metadata_changes:
        status = Status.METADATA_ONLY
    else:
        status = Status.UNCHANGED

    return DiffEntry(path=path, name=os.path.basename(path) or "/", status=status, kind="file",
                      original_inode=orig, local_path=local_path, local_stat=st,
                      metadata_changes=metadata_changes)


def _classify_nonfile(fs: FilesystemImage, path: str, orig: Inode, st: os.stat_result,
                       local_path: str, kind: str, suppress_uid_gid: bool = False) -> DiffEntry:
    orig_uid, orig_gid = _resolve_uid_gid(fs, orig)
    local_mode = statmod.S_IMODE(st.st_mode)
    orig_mode = orig.mode & 0o7777
    local_mtime = int(st.st_mtime)

    metadata_changes = {}
    content_changed = False

    if kind == "symlink":
        local_target = os.readlink(local_path).encode("utf-8", "surrogateescape")
        if local_target != orig.symlink_target:
            content_changed = True
            metadata_changes["symlink_target"] = (orig.symlink_target, local_target)
    elif kind in ("chrdev", "blkdev"):
        local_rdev = st.st_rdev
        if local_rdev != orig.rdev:
            content_changed = True
            metadata_changes["rdev"] = (
                f"{orig.rdev >> 8}:{orig.rdev & 0xff}",
                f"{os.major(local_rdev)}:{os.minor(local_rdev)}",
            )
    # fifo/socket/dir have no content beyond metadata; dir's "content"
    # (its children) is handled by the tree walk, not here.

    if local_mode != orig_mode:
        metadata_changes.setdefault("mode", (oct(orig_mode), oct(local_mode)))
    if not suppress_uid_gid and orig_uid is not None and st.st_uid != orig_uid:
        metadata_changes.setdefault("uid", (orig_uid, st.st_uid))
    if not suppress_uid_gid and orig_gid is not None and st.st_gid != orig_gid:
        metadata_changes.setdefault("gid", (orig_gid, st.st_gid))
    if kind != "dir" and local_mtime != orig.mtime:
        metadata_changes.setdefault("mtime", (orig.mtime, local_mtime))

    if content_changed:
        status = Status.MODIFIED
    elif metadata_changes:
        status = Status.METADATA_ONLY
    else:
        status = Status.UNCHANGED

    return DiffEntry(path=path, name=os.path.basename(path) or "/", status=status, kind=kind,
                      original_inode=orig, local_path=local_path, local_stat=st,
                      metadata_changes=metadata_changes)


def compute_diff(fs: FilesystemImage, source_dir: str) -> DirectoryDiff:
    """Compare fs's already-parsed original tree against source_dir on
    disk. Returns a DirectoryDiff covering every path on either side.

    If source_dir contains a `.sqpack_meta.json` sidecar (written by
    --reconstruct for exactly this purpose), paths it lists as
    "skipped_special_nodes" (device/fifo/socket nodes that couldn't be
    created without root) are treated as expected-absent rather than
    REMOVED -- extracting a tree and immediately feeding it back as
    --source-dir with no edits must not falsely report 60 device nodes
    as deleted."""
    if fs.root is None:
        fs.build_tree()

    expected_absent = set()
    sidecar_found = False
    sidecar = _load_sidecar(source_dir)
    if sidecar is not None:
        sidecar_found = True
        schema_version = sidecar.get("schema_version", 1)
        if schema_version not in (1, 2):
            # Forward-compatible: accept unknown schemas, just don't trust
            # unrecognized fields. schema 1: skipped_special_nodes only.
            # schema 2: + source_image, source_sha256, extracted_at.
            pass
        expected_absent = {e["path"] for e in sidecar.get("skipped_special_nodes", [])}

    # Bug 2b fix: detect the "every file owned by the extracting user
    # instead of the image's real uid/gid" pattern -- true of ANY non-root
    # extraction, sqpack's own --reconstruct included, not just unsquashfs.
    # When detected, uid/gid differences are never reported as real changes
    # (see _classify_file/_classify_nonfile's suppress_uid_gid parameter);
    # the repacker always uses the ORIGINAL image's uid/gid for content it
    # reuses regardless, so this only affects what gets *reported*, not
    # what gets *written*.
    suppress_uid_gid = False
    if fs.sb.no_ids == 1 and fs.id_table:
        original_value = fs.id_table[0]
        uniform_local = _scan_uniform_uid_gid(source_dir)
        if uniform_local is not None and uniform_local != (original_value, original_value):
            suppress_uid_gid = True

    diff = DirectoryDiff()
    original_by_path: Dict[str, FSNode] = {n.path: n for n in iter_nodes(fs.root)}

    def local_path_for(image_path: str) -> str:
        rel = image_path.lstrip("/")
        return os.path.join(source_dir, rel) if rel else source_dir

    visited_image_paths = set()

    def walk_source(image_path: str):
        local_path = local_path_for(image_path)
        try:
            st = os.lstat(local_path)
        except FileNotFoundError:
            return  # shouldn't happen; caller only recurses into dirs it just lstat'd

        visited_image_paths.add(image_path)
        kind = _KIND_BY_STMODE.get(statmod.S_IFMT(st.st_mode), None)
        if kind is None:
            return  # unsupported local file type (e.g. a socket file we can't classify) -- skip

        orig_node = original_by_path.get(image_path)

        if orig_node is None:
            # ADDED -- no counterpart in the original image at all.
            entry = DiffEntry(path=image_path, name=os.path.basename(image_path) or "/",
                               status=Status.ADDED, kind=kind, local_path=local_path, local_stat=st)
            diff.entries[image_path] = entry
            _bucket(diff, entry)
        else:
            orig = orig_node.inode
            if orig.kind != kind:
                entry = DiffEntry(path=image_path, name=os.path.basename(image_path) or "/",
                                   status=Status.TYPE_CHANGED, kind=kind, original_inode=orig,
                                   local_path=local_path, local_stat=st,
                                   metadata_changes={"kind": (orig.kind, kind)})
                diff.entries[image_path] = entry
                _bucket(diff, entry)
            elif kind == "file":
                entry = _classify_file(fs, image_path, orig, st, local_path, suppress_uid_gid)
                diff.entries[image_path] = entry
                _bucket(diff, entry)
            elif kind == "dir":
                entry = _classify_nonfile(fs, image_path, orig, st, local_path, kind, suppress_uid_gid)
                diff.entries[image_path] = entry
                _bucket(diff, entry)
            else:
                entry = _classify_nonfile(fs, image_path, orig, st, local_path, kind, suppress_uid_gid)
                diff.entries[image_path] = entry
                _bucket(diff, entry)

        if kind == "dir":
            try:
                child_names = sorted(os.listdir(local_path))
            except OSError:
                child_names = []
            for name in child_names:
                # Skip sqpack's own bookkeeping sidecars at the root.
                # Both .sqpack_meta.json (source_image metadata) and
                # .sqpack_devices (the mksquashfs -pf replacement) live
                # in the root of source_dir after --reconstruct. Without
                # this filter they get classified as ADDED regular files
                # and inflate inode_count by 1 (and bloat bytes_used).
                if image_path == "/" and name in (_SIDECAR_FILENAME, _DEVICES_FILENAME):
                    continue
                child_image_path = (image_path.rstrip("/") + "/" + name) if image_path != "/" else "/" + name
                walk_source(child_image_path)

    walk_source("/")

    # Apply the proprietary .sqpack_devices sidecar: every entry that
    # exists in source_dir's sidecar (and is NOT already in the original
    # tree) becomes an ADDED special inode. The sidecar is the
    # sqpack-proprietary replacement for `mksquashfs -pf` — it lets the
    # user add new device/fifo/socket nodes that couldn't have existed
    # in source-dir at all (because mknod requires root). Paths that
    # ARE in the original tree but absent from the local directory
    # (e.g. /dev/zero where mknod failed) are NOT touched here; the
    # REMOVED-loop below already preserves them from the original
    # verbatim, which is the right behavior for an unmodified round-trip.
    devices_sidecar_path = os.path.join(source_dir, _DEVICES_FILENAME)
    if os.path.isfile(devices_sidecar_path):
        device_entries = pseudo.load(devices_sidecar_path)
        for dentry in device_entries:
            path = dentry.path
            if path in visited_image_paths:
                # Sidecar entry was materialized on disk this time
                # (e.g. user ran with sudo) -- the regular walk already
                # handled it. Nothing to do.
                continue
            if path in original_by_path:
                # Original image had this special node but source-dir
                # doesn't (mknod failed). The REMOVED-loop handles
                # this case by preserving the original. Sidecar is
                # informational only -- don't override.
                continue
            # Brand-new special inode added via the sidecar.
            synthetic_st = _synth_stat_for_device(dentry)
            entry = DiffEntry(
                path=path,
                name=os.path.basename(path) or "/",
                status=Status.ADDED,
                kind=dentry.kind,
                local_path=os.path.join(source_dir, path.lstrip("/")),
                local_stat=synthetic_st,
                device_meta=dentry,
            )
            diff.entries[path] = entry
            _bucket(diff, entry)

    # REMOVED -- present in the original tree, never visited above.
    # EXCEPTION (Bug 2a): device/fifo/socket nodes that are absent are, in
    # the overwhelming majority of cases, a permission limitation (mknod
    # needs root), not a deliberate deletion -- true whether or not a
    # sidecar is present (an externally-extracted tree, e.g. via plain
    # unsquashfs, never has one at all). These are preserved verbatim from
    # the original by simply NOT excluding them from the merged tree --
    # they get no DiffEntry, and the repacker's merge step already copies
    # anything not explicitly marked REMOVED from the original untouched.
    # We still record an UNCHANGED entry for them here purely so counts
    # and --diff-detail reporting reflect them accurately.
    for path, node in original_by_path.items():
        if path == "/":
            continue
        if path in visited_image_paths:
            continue
        if node.inode.kind in _SPECIAL_KINDS:
            entry = DiffEntry(path=path, name=node.name, status=Status.UNCHANGED,
                               kind=node.inode.kind, original_inode=node.inode)
            diff.entries[path] = entry
            continue
        entry = DiffEntry(path=path, name=node.name, status=Status.REMOVED, kind=node.inode.kind,
                           original_inode=node.inode)
        diff.removed_paths_all_kinds.append(path)
        if node.inode.kind == "file":
            diff.removed_files.append(path)

    return diff


def _bucket(diff: DirectoryDiff, entry: DiffEntry) -> None:
    if entry.status == Status.UNCHANGED:
        if entry.kind == "file":
            diff.unchanged_files.append(entry.path)
        return
    if entry.status == Status.METADATA_ONLY:
        diff.metadata_only_changes.append(entry.path)
        return
    if entry.status == Status.TYPE_CHANGED:
        diff.type_changed.append(entry.path)
        return
    if entry.status == Status.MODIFIED:
        if entry.kind == "file":
            diff.modified_files.append(entry.path)
        elif entry.kind == "symlink":
            diff.changed_symlinks.append(entry.path)
        elif entry.kind in ("chrdev", "blkdev"):
            diff.changed_devices.append(entry.path)
        elif entry.kind == "fifo":
            diff.changed_fifos.append(entry.path)
        elif entry.kind == "socket":
            diff.changed_sockets.append(entry.path)
        elif entry.kind == "dir":
            diff.changed_directories.append(entry.path)
        return
    if entry.status == Status.ADDED:
        if entry.kind == "file":
            diff.added_files.append(entry.path)
        return


def format_verbose_lines(diff: DirectoryDiff) -> List[str]:
    """One line per non-unchanged path, in the shape --verbose logging
    wants: 'STATUS  /path'. Unchanged paths are intentionally omitted
    here (they're summarized as a count) to keep verbose output focused
    on what actually changed, per the logging requirement."""
    lines = []
    for path, entry in sorted(diff.entries.items()):
        if entry.status == Status.UNCHANGED:
            continue
        lines.append(f"{entry.status.value:<14}{path}")
    for path in sorted(diff.removed_paths_all_kinds):
        lines.append(f"{'REMOVED':<14}{path}")
    return lines
