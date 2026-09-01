"""
sqfs_repacker
=============
Deterministic SquashFS 4.x analysis, extraction, repacking, and
comparison toolkit.

Organized into four phases, each independently usable:

    Phase 1  analyzer.py      -- read-only forensic analysis
    Phase 2  reconstruct.py   -- full metadata parse + file extraction
    Phase 3  repacker.py      -- deterministic rebuild, with patching
                                  and --source-dir directory diffing
    Phase 4  compare.py       -- structured diff between two images

End users should generally prefer the unified CLI (`sqpack.py` at the
repo root, or the `sqpack` console script after `pip install .`) over
calling these phases directly -- see sqpack.py's --help.

Note on names: `reconstruct` and `compare` are NOT re-exported as bare
top-level names here, deliberately -- both are also the name of their
own submodule (reconstruct.py, compare.py), and re-exporting a function
under the same name as its submodule shadows the submodule attribute on
this package, breaking `from sqfs_repacker import reconstruct` /
`compare` used internally by cli.py/sqpack.py to reach the MODULE, not
the function. Use `sqfs_repacker.reconstruct.reconstruct(...)` and
`sqfs_repacker.compare.compare(...)` (or `from sqfs_repacker.reconstruct
import reconstruct`) for library use instead.

Example (library use, no CLI):

    from sqfs_repacker import analyze, Repacker, FilesystemImage
    from sqfs_repacker.reconstruct import reconstruct
    from sqfs_repacker.compare import compare

    report = analyze("firmware.squashfs")
    print(report.reproducibility_verdict)

    fs = FilesystemImage("firmware.squashfs")
    fs.build_tree()
    new_bytes, stats = Repacker(fs).build({"/etc/issue": b"patched\\n"})
"""

__version__ = "1.12.1"

from .analyzer import analyze, AnalysisReport
from .reconstruct import ReconstructionReport
from .repacker import Repacker, RepackStats
from .compare import ComparisonReport
from .tree import FilesystemImage
from .directory_diff import DirectoryDiff, DiffEntry, Status

__all__ = [
    "__version__",
    "analyze", "AnalysisReport",
    "ReconstructionReport",
    "Repacker", "RepackStats",
    "ComparisonReport",
    "FilesystemImage",
    "DirectoryDiff", "DiffEntry", "Status",
]
