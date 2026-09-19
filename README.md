# sqpack — Deterministic SquashFS Analysis, Extraction & Repacking Toolkit

> **New: `case_studies/`** — a real-world SquashFS v4/xz-on-UBI rootfs
> recovery as a documented case study with a self-contained diagnostics module
> (`sqfs_repacker/case_studies/`). Read-only reference code for future
> releases; not wired into any CLI operation. See `case_studies/README.md`.

A complete Python toolkit for working with SquashFS 4.x firmware images:
deep read-only **analysis**, metadata-exact **extraction**, deterministic
**repacking** (only changed files are recompressed — everything else is reused
byte-for-byte), and structured **comparison** between two images.

Built for firmware reversing workflows where round-trip fidelity matters: an
untouched extract → repack produces an output **byte-identical** to the
original (verified by `--self-test`).

```
sqpack firmware.squashfs --analyze        # forensic analysis + reproducibility verdict
sqpack firmware.squashfs -R -x rootfs/    # metadata-exact extraction (root preserves devices)
sqpack rootfs/ patched.squashfs           # repack: only edited files recompressed
```

---

## Requirements

**No third-party runtime dependencies.** The core toolkit runs purely on the
Python standard library (`lzma`, `zlib`, `struct`, …) — nothing else to
install.

| Dependency | Required? | Install command |
|---|---|---|
| Python 3.8+ | ✅ required | system Python (see below) |
| `lz4` (LZ4 compression) | ⚪ optional | `uv tool install --with lz4 .` or `pip install lz4` |
| `zstandard` (ZSTD compression) | ⚪ optional | `uv tool install --with zstandard .` or `pip install zstandard` |
| `lzo` decoder | ❌ none exists | LZO is detected & reported, but has no pure-Python decoder — clear error, never fabricated output |

The optional packages are only needed **if you repack or analyze images that
use that compressor**:

```sh
# both optional compressors in one shot (uv)
uv tool install --with lz4 --with zstandard ./

# or via pip
pip install .[lz4,zstd]
```

If none of your target images use LZ4 or ZSTD, install as-is — the tool works
fully with zero extra packages.

---

## Installation

There are five ways to install it. Pick one.

### Option A — self-install (no pip/uv/venv needed, recommended)

Since v1.13.0 sqpack manages its own installation: it copies the pure-stdlib
package under `--prefix` and writes a `sqpack` shim, tracked by an uninstall
manifest. No pip, no uv, no virtualenv, no sudo (default prefix `~/.local`).

```sh
# from a release tarball or a git clone of this repo
python3 -m sqfs_repacker.sqpack --install     # or: ./sqpack.py --install
```

Lifecycle shortcuts:

| Command | Effect |
|---|---|
| `sqpack --install` | install / upgrade in place (idempotent) |
| `sqpack --upgrade` | fetch the latest tarball from GitHub and reinstall |
| `sqpack --upgrade-url URL` | upgrade from a custom tarball URL or local path |
| `sqpack --uninstall` | manifest-driven uninstall (removes only what it created) |
| `sqpack --uninstall --force` | also remove a foreign (non-lifecycle) shim |
| `sqpack --clean DIR` | list generated extraction artifacts (`*.extracted/`, `squashfs-root*/`, `.sqpack_meta.json`) — dry run |
| `sqpack --clean DIR --yes` | apply the cleanup |
| `sqpack ... --prefix DIR` | install location (default `~/.local`) |

A pre-existing non-lifecycle `sqpack` shim (uv/pipx/pip) is never silently
replaced — it is backed up to `sqpack.pre-lifecycle` first. GitHub-upgrade
works from the very first self-install:

```sh
python3 -m sqfs_repacker.sqpack --install   # once
sqpack --upgrade                            # every later version
```

### Option B — `uv tool install` (isolated, pre-built venv)

Installs `sqpack` as a standalone command in its own virtual environment:

```sh
# from the toolkit directory
uv tool install ./sqpack_toolkit_v1.0

# or from anywhere, pointing at the directory
uv tool install /path/to/sqpack_toolkit_v1.0

# or straight from the built wheel (see Option D)
uv tool install ./dist/sqfs_repacker-<version>-py3-none-any.whl
```

The installed executable is named **`sqpack`**:

```sh
$ sqpack --version
sqpack 1.13.0
```

Include optional compressors at install time:

```sh
uv tool install --with lz4 --with zstandard ./sqpack_toolkit_v1.0
```

### Option C — `pip install` (into your current Python environment)

```sh
pip install .                      # from inside the toolkit directory
# or
pip install .[lz4,zstd]            # with optional LZ4/ZSTD support
```

This also exposes the `sqpack` command.

### Option D — install from the prebuilt distribution files

`dist/` contains both packaging formats, built from this exact tree:

```sh
uv tool install ./dist/sqfs_repacker-<version>-py3-none-any.whl   # wheel
pip install ./dist/sqfs_repacker-<version>-py3-none-any.whl
pip install ./dist/sqfs_repacker-<version>.tar.gz                 # sdist
```

### Option E — no install at all (standalone launcher)

The top-level `sqpack.py` is a zero-dependency launcher: it puts the package's
parent directory on `sys.path` and works from any working directory.

```sh
python3 sqpack.py firmware.squashfs --analyze
python3 sqpack.py --version
```

### Verifying the install

```sh
sqpack --version                      # → sqpack 1.13.0
sqpack image.squashfs --analyze       # real image analysis (+ anomaly scan)
sqpack image.squashfs --self-test     # identity round-trip + lifecycle round-trip: PASS/FAIL
python3 -m unittest tests.test_lifecycle -v   # test suite (from the repo root)
```

---

## Quick start

```sh
# Analyze an image (read-only, safe)
sqpack firmware.squashfs --analyze

# Extract the full tree, preserving mtime/mode/uid/gid/hardlinks
sqpack firmware.squashfs --reconstruct --extract rootfs

# Edit anything under rootfs/, then rebuild — only changed files recompressed
$EDITOR rootfs/etc/init.d/rcS
sqpack firmware.squashfs --repack patched.squashfs --source-dir rootfs

# Or the shorthand form (explicit source image)
sqpack -s firmware.squashfs rootfs/ patched.squashfs

# Compare two images
sqpack firmware.squashfs --compare patched.squashfs

# Verify byte-fidelity of your whole workflow
sqpack firmware.squashfs --verify --source-dir rootfs

# Anomaly scan — structural checks run on every --analyze; add a known-good
# reference to enable bit-rot detection/repair (exit 3 until you pass --yes)
sqpack firmware.squashfs --analyze
sqpack firmware.squashfs --analyze --reference known-good.squashfs
sqpack firmware.squashfs --analyze --reference known-good.squashfs --yes   # → firmware.fixed.squashfs

# Lifecycle
sqpack --install      # self-install under ~/.local; later updates: sqpack --upgrade
```

Run `sqpack --help` for the complete reference.

---

## Short flags (v1.4+)

```
-a analyze    -R reconstruct   -r repack       -c compare
-V verify     -t self-test     -d source-dir   -s source
--install / --uninstall / --upgrade / --clean PATH ...    lifecycle (v1.13.0)
-p patch      -x extract       -o output       -k keep-temp
-n analysis-dir -m manifest    -j json         -l log
-v verbose    -q quiet         -h help
```

All long flags remain supported; short flags are additive.

---

## The directory-based workflow

```sh
sqpack firmware.squashfs -R -x squashfs-root      # extract
# ... edit anything under squashfs-root/ ...
sqpack squashfs-root/                            # repacks into ./squashfs-root.squashfs
# explicit source + output
sqpack -s firmware.squashfs squashfs-root/ patched.squashfs
```

Only files that actually changed are recompressed; everything else is
byte-identical to the source.

### `--source-dir`: rebuild from an edited directory tree

```sh
# 1. extract
sqpack firmware.squashfs --reconstruct --extract squashfs-root

# 2. edit however you like — any combination of:
$EDITOR squashfs-root/etc/issue          # modify content
rm squashfs-root/etc/old-service.conf    # remove a file
echo hi > squashfs-root/etc/new.txt      # add a file
chmod 600 squashfs-root/etc/shadow       # metadata-only change
mkdir squashfs-root/etc/empty_dir        # add an empty directory

# 3. rebuild — everything is detected automatically
sqpack firmware.squashfs --repack rebuilt.squashfs --source-dir squashfs-root
```

Every path is classified as **UNCHANGED / MODIFIED / ADDED / REMOVED /
METADATA_ONLY / TYPE_CHANGED** recursively. Use `--diff-detail [N]` to see
*why* each path changed (which metadata fields differ).

**Identity rebuild:** if the directory is untouched, the output is the
original file byte-for-byte:

```
$ sqpack firmware.squashfs --repack copy.squashfs --source-dir squashfs-root
Mode: identity
Nothing to change -- output is the ORIGINAL file, byte-for-byte.
$ cmp firmware.squashfs copy.squashfs && echo IDENTICAL
IDENTICAL
```

**Hardlinks** are preserved, split, and merged correctly across a round trip
(verified: a pair that shares an inode stays shared; changing one path splits
it; hardlinking a new path to an existing unchanged file merges into the same
inode).

### Mixed mode: `--source-dir` + `--patch` together

```sh
sqpack firmware.squashfs --repack rebuilt.squashfs \
    --source-dir squashfs-root \
    --patch /etc/issue=one_more_override.txt
```

The directory scan is applied first; `--patch` is applied on top and **wins**
on any path both mention.

---

## Architecture

Four independent phases, each usable on its own, with a single unified CLI:

```
Phase 1  analyzer.py     read-only forensic analysis + reproducibility verdict
Phase 2  reconstruct.py  full metadata parse + file extraction
                         (preserves mtime/mode/uid/gid/hardlinks; real mknod as root)
Phase 3  repacker.py     deterministic rebuild — one shared engine for both
                         --patch and --source-dir (directory_diff detects, repacker builds)
Phase 4  compare.py      structured diff between two images
```

`repacker.py`'s `Repacker.build()` is the **only** place that writes image
bytes, regardless of whether the change list came from `--patch`,
`--source-dir`, or both — there is exactly one tree-walk, one
table-serialization routine, and one superblock assembly step.

`directory_diff.py` (comparison only) uses a fast path first (size + mtime +
mode + type, no hashing), hashing content only when genuinely ambiguous —
the standard rsync-style quick check, so trees with hundreds of thousands of
files stay usable.

---

## Known limitations (stated plainly)

- **Metadata tables (inode/directory/fragment/id) are always freshly rebuilt
  when anything changes** — never byte-reused, even for inodes whose logical
  content is identical. Inherent SquashFS format property: those tables store
  absolute offsets, and any size change anywhere cascades.
  `--compare`/`--verify` show this precisely.
- **`EXTENDED_DIR`** (xattr'd directories, or a single listing over 65535
  bytes) is not implemented — raises a clear error rather than emit malformed
  data.
- **Export/lookup table and xattr table are not rebuilt** on repack (written
  as absent).
- **`--source-dir`'s fast-path comparison** trusts a size+mtime match as proof
  content is unchanged, without hashing — a deliberate, documented trade-off
  for scaling to large trees.
- **`--source-dir` with an *unsquashfs*-extracted tree may show spurious
  `METADATA_ONLY` entries** where unsquashfs didn't preserve the original
  mtime. Harmless (data blocks are still reused verbatim; only the inode
  mtime field is rewritten). Use `sqpack --reconstruct` instead of unsquashfs
  to avoid it entirely — it preserves mtime/mode/uid/gid/hardlinks and the
  round trip is byte-identical (verified by `--self-test`).
- **LZMA block framing** may vary between images: `compressor.py` auto-detects
  it (standard framing first, then alternate framings via bounded brute force)
  and remembers what worked for the rest of that image; `encoder.py` writes
  new content back out using whichever framing was detected.
- Directory entries are written one-header-per-entry rather than
  grouped by block — fully spec-valid, just a few bytes less
  space-efficient per entry.

---

## Project structure

```
sqpack.py                  # standalone launcher — `python3 sqpack.py ...` from anywhere
pyproject.toml             # packaging — `pip install .` / `uv tool install` exposes `sqpack`
README.md                  # this file
LICENSE                    # full license terms
dist/                      # prebuilt wheel + sdist (from this exact tree)
sqfs_repacker/
  sqpack.py                 # dispatcher: operations -> phases, incl. --source-dir wiring
  cli.py                    # old per-phase CLI, unchanged, still usable directly
  constants.py, superblock.py, layout.py, toolcheck.py       # Phase 1
  analyzer.py
  compressor.py, metadata_reader.py, inode_structs.py,
  inode_parser.py, directory_parser.py, tables.py, tree.py    # Phase 2
  reconstruct.py                                               # + hardlink/mtime/mode preservation
  directory_diff.py                                            # comparison only, no rebuilding
  encoder.py, table_builder.py                                 # Phase 3
  repacker.py                                                   # shared rebuild engine (--patch AND --source-dir)
  compare.py                                                    # Phase 4
  sqfs_anomaly.py                                               # anomaly scan (structural + bit-rot vs --reference)
  lifecycle.py                                                  # self-install / uninstall / upgrade / clean
```

---

## Changelog highlights

**v1.13.0 — anomaly engine + lifecycle self-management:**
- `sqfs_anomaly.py`: structural integrity scan on every `--analyze`
  (truncation, table offsets, ordering, metadata sanity) plus bit-rot
  detection/repair against `--reference` — repairable rot fail-fasts with
  exit 3 unless `--yes`; `--yes` writes `<image>.fixed.squashfs`;
  `--dry-run` reports only.
- `--install` / `--uninstall` / `--upgrade` / `--clean PATH`: self-managed
  install (manifest-driven, stdlib-only, no pip/uv/venv/sudo); foreign shims
  are backed up to `<name>.pre-lifecycle`, never clobbered.
- First test suite (`tests/test_lifecycle.py`, 9 unittests) and a lifecycle
  round-trip inside `--self-test`.

**v1.4+** — directory-based workflow (`sqpack DIR [OUTPUT]` / `-s`), short
flags, verbose per-phase timing.

**v1.2 — production-readiness fixes:**
- False `BLOCKED` verdict on `--analyze` fixed (permission-only unsquashfs
  failures no longer misclassified as LZMA decode failures).
- `--source-dir` no longer reports device/fifo/socket nodes as removed (they
  can't be created without root — now correctly preserved).
- Uniform extraction-artifact ownership (whole tree owned by one different
  uid/gid) no longer reported as a metadata change.
- `mkfs_time` preserved by default on any rebuild (`--preserve-timestamp`
  default; `--new-timestamp` / `--current-timestamp` to override).
- `--reconstruct` now really attempts `mknod`/`mkfifo` as root instead of
  unconditionally skipping device nodes.
- New `--self-test IMAGE` (extract → rebuild → compare → PASS/FAIL with size +
  SHA-256) and `--diff-detail [N]` (per-path change categories and metadata
  fields).

---

## License

**Copyright © 2026 Bharatiy — All Rights Reserved.**

This software and associated documentation files are the exclusive property of
the copyright holder. Unauthorized copying, modification, distribution, or
use of this software, via any medium, is strictly prohibited without the
prior written permission of the copyright holder.

See the [LICENSE](LICENSE) file for the full terms.
