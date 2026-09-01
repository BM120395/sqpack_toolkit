#!/usr/bin/env python3
"""
sqpack.py (top-level launcher)
================================
Standalone entry point: run this directly with `python3 sqpack.py ...`
from any working directory, with no installation required. It exists
purely to make the sqfs_repacker package importable regardless of where
it's invoked from -- the actual CLI logic lives in
sqfs_repacker/sqpack.py, reusable both by this launcher and by the
`sqpack` console-script entry point installed via pyproject.toml.

Why this matters: the previous `python3 cli.py` entry point failed with
"attempted relative import with no known parent package" if you ran it
from inside the sqfs_repacker/ directory itself, because a script run
directly has no package context for its `from . import ...` lines to
resolve against. This launcher sidesteps that by ensuring the package's
PARENT directory is on sys.path before importing it as a proper
package, so it works the same way no matter which directory you're
sitting in when you run it.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from sqfs_repacker.sqpack import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
