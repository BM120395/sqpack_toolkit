"""
pseudo.py
=========

Proprietary sidecar format for device/fifo/socket inodes that cannot be
materialized as actual filesystem nodes during non-root extraction.

Background
----------
`standard readers -d dest` as non-root cannot create character/block devices
(or even FIFOs in some container environments). The kernel device and
pipe metadata is fine inside the SquashFS image — it just won't land
on disk. Likewise, sockets are intentionally never materialized (they
are live IPC endpoints, not file content).

This module defines a small text sidecar `.sqpack_devices` written
alongside `.sqpack_meta.json` during extract. The sidecar mirrors
`reference SquashFS tools -pf` semantics but is sqpack-owned so no external tool is
required. During repack (`--source-dir`), the sidecar is read back and
each entry is mapped to its corresponding FSNode in the merged tree
(preserved, changed, or added).

Format
------
One entry per line, ASCII, `#` for comments. Columns are whitespace-
separated. Path is absolute (starts with `/`). Mode is octal.

  <path>  <mode_octal>  <uid>  <gid>  <kind>  [major  minor]

Kinds:
  c    character device     (extra: major, minor)
  b    block device         (extra: major, minor)
  p    named pipe (FIFO)    (no extra)
  s    socket               (no extra)

Example
-------
  /dev/console  0666  0  0  c  5  1
  /dev/zero     0666  0  0  c  1  5
  /tmp/myfifo   0644  0  0  p

Notes
-----
- Path is stored as-is from the parsed tree (the leading `/` is preserved).
- uid/gid are stored as raw values (not index table lookups); the
  SquashFS id table is generated independently during repack.
- Mode is stored as octal; we use 4-digit octal (e.g. 0666).
- Order is not significant. Entries are written in the order they
  are encountered during tree walk (typically pre-order DFS).
"""

from __future__ import annotations

import os
import stat as statmod
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Tuple


SIDECAR_DEVICES_FILENAME = ".sqpack_devices"


# ---- public dataclass --------------------------------------------------

@dataclass(frozen=True)
class DeviceEntry:
    """One device/fifo/socket inode's persisted metadata."""
    path: str            # absolute path, e.g. "/dev/zero"
    mode: int            # permission bits (S_IFCHR etc. stripped)
    uid: int
    gid: int
    kind: str            # "chrdev", "blkdev", "fifo", "socket"
    rdev: int = 0        # encoded major|minor (mknod-style); 0 for fifo/socket

    @property
    def kind_code(self) -> str:
        return {"chrdev": "c", "blkdev": "b", "fifo": "p", "socket": "s"}[self.kind]

    @property
    def is_device(self) -> bool:
        return self.kind in ("chrdev", "blkdev")

    @property
    def major(self) -> int:
        return os.major(self.rdev) if self.is_device else 0

    @property
    def minor(self) -> int:
        return os.minor(self.rdev) if self.is_device else 0


# ---- serialize / parse -------------------------------------------------

def serialize_entry(e: DeviceEntry) -> str:
    """Render one entry as a single line (no trailing newline)."""
    fields = [e.path, f"{e.mode:04o}", str(e.uid), str(e.gid), e.kind_code]
    if e.is_device:
        fields.extend([str(e.major), str(e.minor)])
    return "  ".join(fields)


def parse_line(line: str) -> Optional[DeviceEntry]:
    """Parse one sidecar line. Returns None for blank/comment lines
    or lines that don't fit the schema (malformed entries are silently
    skipped — we want robustness for hand-edited sidecars)."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) not in (5, 7):
        return None
    path, mode_s, uid_s, gid_s, kind_s, *rest = parts
    # path must be absolute
    if not path.startswith("/"):
        return None
    try:
        mode = int(mode_s, 8)
        uid = int(uid_s)
        gid = int(gid_s)
    except ValueError:
        return None
    code_to_kind = {"c": "chrdev", "b": "blkdev", "p": "fifo", "s": "socket"}
    kind = code_to_kind.get(kind_s)
    if kind is None:
        return None
    if kind in ("chrdev", "blkdev"):
        if len(rest) != 2:
            return None
        try:
            major = int(rest[0])
            minor = int(rest[1])
        except ValueError:
            return None
        rdev = os.makedev(major, minor)
    else:
        rdev = 0
    return DeviceEntry(path=path, mode=mode, uid=uid, gid=gid, kind=kind, rdev=rdev)


def load(sidecar_path: str) -> List[DeviceEntry]:
    """Read every entry from a sidecar file. Missing file = empty list.
    Malformed lines are skipped (line number printed to stderr as a
    warning so users notice typos without their whole extract failing)."""
    if not os.path.isfile(sidecar_path):
        return []
    out: List[DeviceEntry] = []
    with open(sidecar_path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            entry = parse_line(raw)
            if entry is None and raw.strip() and not raw.strip().startswith("#"):
                # Only warn on lines that look like attempts, not blanks/comments
                import sys
                print(
                    f"[sqpack] warning: ignoring malformed {SIDECAR_DEVICES_FILENAME} line {lineno}: {raw.rstrip()}",
                    file=sys.stderr,
                )
            elif entry is not None:
                out.append(entry)
    return out


def append(sidecar_path: str, entry: DeviceEntry) -> None:
    """Append one entry to the sidecar (creates file + header if needed)."""
    is_new = not os.path.isfile(sidecar_path)
    with open(sidecar_path, "a", encoding="utf-8") as f:
        if is_new:
            f.write("# sqpack device/fifo/socket sidecar\n")
            f.write("# <path>  <mode_octal>  <uid>  <gid>  <c|b|p|s>  [major minor]\n")
        f.write(serialize_entry(entry) + "\n")


# ---- filesystem materialize helpers ------------------------------------

def try_mknod(entry: DeviceEntry, target: str) -> bool:
    """Attempt to materialize `entry` at `target` using os.mknod/mkfifo.
    Returns True on success, False on any OSError (e.g. permission denied).

    Note: this is opportunistic — even with CAP_MKNOD you may hit EPERM
    in containerized environments. Sockets are intentionally never
    materialized; they are live IPC endpoints, not file content.
    """
    if entry.kind == "socket":
        return False
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    try:
        if entry.kind == "fifo":
            os.mkfifo(target, entry.mode & 0o7777)
        else:
            dev_type = statmod.S_IFCHR if entry.kind == "chrdev" else statmod.S_IFBLK
            os.mknod(target, dev_type | (entry.mode & 0o7777), entry.rdev)
        os.chmod(target, entry.mode & 0o7777)
        return True
    except (OSError, PermissionError, NotImplementedError):
        return False
