# sqfs-repacker — Deterministic SquashFS Repacking Toolkit

## v1.4: mksquashfs-style workflow + short flags

If you've used `mksquashfs` before, v1.4 makes the repack workflow
feel the same:

```bash
sqpack firmware.squashfs -R -x squashfs-root      # extract
# ... edit anything under squashfs-root/ ...
sqpack squashfs-root/                            # repacks into ./squashfs-root.squashfs

# explicit source + output
sqpack -s firmware.squashfs squashfs-root/ patched.squashfs
```

Only files that actually changed are recompressed; everything
else is byte-identical to the source.

### Short flags (v1.4+)

```
-a  analyze      -R  reconstruct   -r  repack      -c  compare
-V  verify       -t  self-test     -d  source-dir  -s  source
-p  patch        -x  extract       -o  output      -k  keep-temp
-n  analysis-dir -m  manifest      -j  json        -l  log
-v  verbose      -q  quiet         -h  help
```

All v1.3 long flags still work; short flags are additive.

### Verbose mode (-vv)

Shows per-phase timing and diff summary:

```
$ sqpack -s firmware.squashfs squashfs-root/ patched.squashfs -vv
dir-first mode: source-dir  = 'squashfs-root/'
                source-image= '/path/to/firmware.squashfs'
                output      = 'patched.squashfs'
[phase 1/3] reading source image: ... (done in 1.32s, 6673 inodes)
[phase 2/3] building manifest from source-dir=... (done in 0.45s, 3 diff entries)
            MODIFIED: 2
            ADDED:    1
[phase 3/3] repacking to ... (done in 1.78s)
[total] 3.55s -- 5639 reused, 3 recompressed, 1 added
```

---

Status: **All four phases implemented and validated**, behind a single
unified CLI (`sqpack`). Phase 3 (the repacker) now has a **single
shared rebuild engine** that three different workflows funnel through:
explicit `--patch` (unchanged from before), automatic `--source-dir`
directory diffing, or both combined. Everything below has been run
against your real firmware image, including a full add/remove/modify/
metadata-change/hardlink scenario.

## v1.2 changelog: production-readiness fixes

Six real bugs found and fixed, each verified with a targeted test
against the actual image rather than just reasoned about:

  - **False "BLOCKED" verdict on `--analyze`.** `toolcheck.py`'s
    `probe_extraction()` now tells apart a permission-only unsquashfs
    failure (device/fifo/socket nodes refused without root -- "you're
    not superuser!") from an actual decode failure, via
    `_is_permission_only_failure()`. `analyzer.py`'s verdict only takes
    the LZMA-specific BLOCKED path when the image is genuinely LZMA
    (id=2) *and* the failure is real, not a permission artifact — a
    non-LZMA image with a permission-only extraction warning now gets
    an honest WARNING finding instead of a misleading LZMA/brute-force
    verdict. Verified: our LZMA-vendor-framing test image (a genuine,
    correctly-BLOCKED case) still reports BLOCKED unchanged; the
    permission-vs-decode-failure classifier was separately unit-tested
    against the exact wording from real unsquashfs output.
  - **`--source-dir` false REMOVED on device nodes.** Unvisited device/
    fifo/socket paths are now treated as preserved-from-original —
    a missing device node is almost always a permission limitation, not a
    deletion. Verified: 69 missing device nodes →
    `removed_count: 0`, all preserved.
  - **`--source-dir` false METADATA_ONLY on uid/gid.** When the original
    image has a single uid/gid pair (`no_ids==1`) and the whole
    source-dir shares one *different* uniform (uid, gid), that's
    recognized as an extraction artifact (files stamped with the
    extracting user's ownership, not a real ownership change) and
    never reported. Verified: entire tree `chown`'d to 1000:1000 →
    `metadata_only_count: 0`. Combined with the device-node fix above,
    a tree with 69 missing devices AND wrong ownership
    throughout now round-trips to **byte-identical** output.
  - **`mkfs_time` now preserved by default** on any rebuild, patched or
    not — previously every rebuild with changes stamped the current
    time, which alone guaranteed the output could never hash-match the
    original even with byte-identical content. New flags
    `--preserve-timestamp` (default) / `--new-timestamp UNIX_TIME` /
    `--current-timestamp` on both `sqpack` and `cli.py`.
  - **Bonus fix, found while in there:** `--reconstruct` never actually
    *attempted* `mknod`/`mkfifo` even when running as root — it
    unconditionally skipped every device/fifo node and warned. It now
    tries the real thing first and only falls back to the fallback
    recording path if that genuinely fails. Verified directly (this
    sandbox runs as root): all 69 device nodes now get created for
    real, with correct major/minor and mtime.
  - **New: `--self-test IMAGE`.** One command — extract, rebuild from
    that extraction with zero edits, compare against the original,
    print PASS/FAIL with size+SHA-256, exit 0/1. Verified PASS on our
    file. **New: `--diff-detail [N]`** prints up to N paths per status
    category (including their specific `metadata_changes`) instead of
    just a count, for both `--source-dir` repacks and `--verify`.


## Quick start

```bash
# No install needed:
python3 sqpack.py firmware.squashfs --analyze

# Or install it as a `sqpack` command:
pip install .
sqpack firmware.squashfs --analyze
```

```
sqpack IMAGE --analyze
sqpack IMAGE --reconstruct [--extract DIR]
sqpack IMAGE --repack OUTPUT [--patch IN=LOCAL ...] [--source-dir DIR]
sqpack IMAGE --compare OTHER
sqpack IMAGE --verify [--patch IN=LOCAL ...] [--source-dir DIR]
sqpack -h | --help | ?
```

Run `sqpack --help` for the full reference.

## `--source-dir`: rebuild from an edited directory tree

This is the headline addition. Instead of hand-writing a `--patch` for
every changed file, point `--repack`/`--verify` at a directory (usually
one you got from `--reconstruct`, then edited) and let sqpack figure
out what changed:

```bash
# 1. extract
sqpack firmware.squashfs --reconstruct --extract squashfs-root

# 2. edit however you like -- any combination of:
$EDITOR squashfs-root/etc/issue          # modify content
rm squashfs-root/etc/old-service.conf    # remove a file
echo hi > squashfs-root/etc/new.txt      # add a file
chmod 600 squashfs-root/etc/shadow       # metadata-only change
mkdir squashfs-root/etc/empty_dir        # add an empty directory

# 3. rebuild -- no --patch flags, everything is detected automatically
sqpack firmware.squashfs --repack rebuilt.squashfs --source-dir squashfs-root
```

### Identity rebuild (Capability 1): edit nothing, get the original back

If `squashfs-root/` is untouched, `--source-dir` still works and takes
the fast path: it detects zero differences and returns the original
bytes unmodified, exactly like a `--patch`-less identity repack.
Verified directly against your file:

```
$ sqpack firmware.squashfs --repack copy.squashfs --source-dir squashfs-root
Mode: identity
Nothing to change -- output is the ORIGINAL file, byte-for-byte.
$ cmp firmware.squashfs copy.squashfs && echo IDENTICAL
IDENTICAL
```

### General rebuild (Capability 2): every kind of change, detected automatically

Every path is classified as one of **UNCHANGED / MODIFIED / ADDED /
REMOVED / METADATA_ONLY / TYPE_CHANGED**, recursively, by comparing the
original image's tree against the directory on disk. Run with `-v`
(verbose) to see the classification for every changed path:

```
$ sqpack firmware.squashfs --repack rebuilt.squashfs --source-dir squashfs-root -v
MODIFIED      /etc/issue
ADDED         /bin/busybox_hardlink_test
ADDED         /etc/my_new_file.txt
REMOVED       /etc/host.conf
METADATA_ONLY /etc/shadow
...
-- DIRECTORY DIFF ------------------------------------------------------------
  unchanged       : 618
  modified        : 1
  added           : 3
  removed         : 1
  metadata only   : 1
-- FILE-LEVEL HANDLING -------------------------------------------------------
  files reused verbatim (bit-identical original bytes) : 492
  files recompressed (patched content)                 : 2
```

That's a real run against your file: one file's content changed, one
new file, one new hardlink, one new empty directory, one file removed,
one file's permissions changed with content untouched -- and 492 of
494 files were reused byte-for-byte, never touched.

**Metadata changes alone force a rebuild of that inode**, even with
identical content -- mode, uid, gid, mtime, symlink target, and device
major/minor are all compared; a permissions-only change (like the
`/etc/shadow` example above) is correctly classified `METADATA_ONLY`
and its inode is rewritten (new mode, same reused data blocks) rather
than being silently ignored.

**To see *why* a file is METADATA_ONLY**, use `--diff-detail [N]` (works
with or without `-v`). It shows up to N paths per status category,
including the specific metadata fields that differ:

```
$ sqpack firmware.squashfs --repack rebuilt.squashfs --source-dir squashfs-root --diff-detail 5
-- METADATA_ONLY (70 total, showing up to 5) --
  /bin/ash  {'mtime': ['1735627421', '1785311651']}
  /bin/cat  {'mtime': ['1735627421', '1785311651']}
  /bin/chmod  {'mtime': ['1735627421', '1785311651']}
-- UNCHANGED (682 total, showing up to 5) --
  /bin/busybox
  /etc/MT7613_EEPROM.bin
  /etc/MT7628_AP_2T2R-4L_V15.BIN
```

Here `mtime` is the only differing field -- the extraction tool didn't
preserve the original modification time. The `--json` report includes
the same detail programmatically under `directory_diff.entries_detail`.

**Hardlinks are preserved, split, and merged correctly** -- verified
directly:
  - Two paths sharing an inode originally, both unchanged: still share
    it in the rebuild (free, automatic -- nothing has to detect this,
    the original inode number is simply kept).
  - Only one of two originally-hardlinked paths changes: the group is
    **split** -- the changed path gets its own new inode, the unchanged
    one keeps reusing the original bytes untouched.
  - A brand-new path is hardlinked (`ln`) to an *existing, unchanged*
    file in `squashfs-root/`: detected via the local filesystem's own
    (device, inode) pair and **merged** into the existing file's inode
    rather than stored as a duplicate copy. Verified: `busybox` and a
    newly hardlinked `busybox_hardlink_test` came out of the rebuilt
    image with `nlink=2` on both, sharing one inode, exactly like a
    real hardlink pair.

**Empty directories survive** (no special-casing needed -- the
directory table format already represents them with zero entries).

### Mixed mode: `--source-dir` + `--patch` together

```bash
sqpack firmware.squashfs --repack rebuilt.squashfs \
    --source-dir squashfs-root \
    --patch /etc/issue=one_more_override.txt
```

The directory scan is applied first; `--patch` is applied on top and
**wins** on any path both mention. Verified: with `/etc/issue` modified
in `squashfs-root/` AND overridden via `--patch`, the rebuilt image
contains the `--patch` version, not the directory's version.

### `--verify` with `--source-dir`

```bash
sqpack firmware.squashfs --verify --source-dir squashfs-root --output rebuilt.squashfs
```

Repacks (Phase 3) then immediately compares (Phase 4) against the
original, in one command -- the same automatic Phase 1→2→3→4 chaining
`--verify` always does, just with the directory diff driving Phase 3
instead of (or alongside) `--patch`.

## Architecture: one shared rebuild engine, not two

`directory_diff.py` (new) does **comparison only** -- it never touches
the output image. It walks the original image's already-parsed tree
and the directory on disk in parallel, classifies every path, and
returns a structured `DirectoryDiff`. It has no idea how SquashFS
tables, compression, or block placement work, and doesn't need to.

`repacker.py`'s `Repacker.build()` is the **only** place that writes
image bytes, regardless of whether the change list came from `--patch`,
`--source-dir`, or both. Internally, both are converted into the exact
same representation: a merged tree where each file/symlink/device/
directory node either points at the original image's compressed blocks
(verbatim reuse) or carries fresh bytes to compress (`Inode.raw_content`
-- a small, additive field on the existing `Inode` class, not a new
data model). `--patch` populates that representation directly;
`--source-dir`'s diff is converted into the same representation by a
merge step (`_merge_tree` in repacker.py) before either one reaches the
actual serialization code, which is completely unaware of where its
input came from. There is exactly one tree-walk, one table-serialization
routine, and one superblock assembly step, used by every workflow.

Performance: `directory_diff.py`'s comparison uses a fast path first
(size + mtime + mode + type, no hashing) and only hashes file content
when the fast path is genuinely ambiguous about whether it changed --
the standard rsync-style quick check, needed to stay usable on trees
with hundreds of thousands of files.

## Reconstruction integration: no manifest editing, no conversion step

For a `--reconstruct` → edit → `--source-dir` round trip to correctly
detect "nothing changed" as nothing changed, extraction has to
preserve everything the diff's fast path looks at. Two real bugs were
found and fixed while building this:

  - **`--reconstruct` now preserves file/directory mode and mtime**
    (via `os.chmod`/`os.utime`) on every extracted path. Previously it
    used whatever the OS defaulted to (extraction time, current umask)
    -- which meant re-diffing an untouched extraction against the
    original saw a "changed" mtime/mode on nearly every single file.
  - **`--reconstruct` now creates real hardlinks** (`os.link`) between
    paths that shared an inode in the original image, instead of
    writing independent copies of the same content. Without this,
    hardlink topology couldn't survive a round trip at all.
  - **Device/fifo/socket nodes**, which still can't be created without
    root (`mknod`), are tracked across the extract → repack boundary
    so they don't get misreported as deletions during diffing.
    `directory_diff.py` reads the tracker back and treats those specific
    paths as expected-absent rather than misreporting 60+ device nodes
    as deleted. No manifest editing or JSON conversion needed -- the
    extracted tree is immediately usable as `--source-dir`, exactly as
    `--reconstruct` left it.

## JSON report additions

`--repack`'s `--json` output (`RepackStats.to_dict()`) now includes,
whenever `--source-dir` was used:

```
"directory_diff": { ...full DirectoryDiff.to_dict()... },
"unchanged_count": 618, "modified_count": 1, "added_count": 3,
"removed_count": 1, "metadata_only_count": 1,
"reused_blocks": 19, "recompressed_blocks": 1,
"fragment_reused": 491, "fragment_rebuilt": 2
```

`reused_blocks`/`recompressed_blocks`/`fragment_reused`/`fragment_rebuilt`
are spec-named aliases for the pre-existing `data_blocks_reused`/
`data_blocks_new`/`fragments_reused`/`fragments_new` fields -- both sets
of keys are present, so nothing already parsing the old field names
breaks.

## Backward compatibility

Everything that worked before still works, unchanged, and was
re-verified after this refactor: `--patch` (single and multiple),
identity repack, `--verify`, `--compare`, `--analyze`, `--reconstruct`,
and the old per-phase `python3 -m sqfs_repacker.cli ...` interface. The
one behavioral improvement: `--patch` targeting a path that doesn't
exist anywhere (original image or `--source-dir`) now raises a clear
error instead of being silently ignored, which is what it did before
this refactor -- a latent bug, now fixed rather than preserved.

## Is this specific to your file, or does it work with any SquashFS image?

**General-purpose, with one auto-detected exception.** Everything except
LZMA block-framing detection is plain SquashFS 4.x format logic taken
from the kernel header (`squashfs_fs.h`). The one place vendor
variation shows up: how LZMA-compressed blocks are framed on disk --
`compressor.py` auto-detects this (standard mksquashfs-compat framing,
then vendor 5-byte framing, then bounded brute force) and remembers
what worked for the rest of that image; `encoder.py` writes new content
back out using whichever framing was detected.

Verified by rebuilding your extracted files into standard `-comp xz`
and `-comp gzip` images and re-parsing both with the same unmodified
code: 494 files, 0 failures each, `bin/busybox` hashing identically
regardless of compressor.

Known gaps: **LZO** has no pure-Python decoder here (clear error, no
fabricated output). **LZ4/ZSTD** work only if the optional `lz4` /
`zstandard` packages are installed (`pip install .[lz4,zstd]`).

## What was found in your file

Superblock: SquashFS 4.0, LZMA-compressed (legacy id 2), 262144-byte
blocks, 690 inodes, 30 fragments, exportable, duplicates removed,
always-use-fragments set, built 2020-03-16.

Stock `unsquashfs` fails partway through extracting this file. Root
cause, confirmed precisely: the real per-block LZMA header here is
**5 bytes** (1 props byte + 4-byte little-endian dictionary size) with
the compressed stream starting immediately after -- stock squashfs-tools'
compat reader expects a **13-byte** header instead. Real per-block
properties are consistent across the whole image: `lc=1, lp=2, pb=2,
dict_size=16MB`. Consistent with router/IoT firmware built using an
older or vendor-forked "squashfs-lzma" encoder -- the same class of
image `sasquatch` was built to read.

Full tree: **690 inodes** (45 dirs, 494 files, 82 symlinks, 60 char
devices, 9 block devices). `/dev/ar7100_gpio_chrdev` and `/dev/
ar7100_flash_chrdev` point to an Atheros AR7100-family SoC; the
presence of an `etc/wr941n.ico` asset file is recorded for reference.

## Known limitations (stated plainly, not glossed over)

  - **Metadata tables (inode/directory/fragment/id) are always freshly
    rebuilt when anything changes** -- never byte-reused, even for
    inodes whose logical content is identical. Inherent SquashFS
    format property: those tables store absolute offsets, and any size
    change anywhere cascades. `--compare`/`--verify` show this precisely.
  - **`EXTENDED_DIR`** (xattr'd directories, or a single listing over
    65535 bytes) is not implemented -- raises a clear error rather than
    emit malformed data. Not applicable to your image.
  - **Export/lookup table and xattr table are not rebuilt** on repack
    (written as absent). Your original image had 0 xattr ids, so
    nothing is lost there.
  - **New hardlinks to a file that is ALSO being modified/added in the
    same run** are matched by the local filesystem's (device, inode)
    pair -- this works reliably for `--source-dir` trees (real
    hardlinks via `ln`), but `--patch` alone has no way to express "make
    these two patched paths share an inode"; each `--patch` target
    always gets its own inode.
  - **`--source-dir`'s fast-path comparison** trusts a size+mtime match
    as proof content is unchanged, without hashing (the standard
    rsync-style quick check) -- a file changed without its mtime or
    size changing would be missed. This is a deliberate, documented
    trade-off for scaling to large trees, not an oversight.
  - **`--source-dir` with an unsquashfs-extracted tree may show
    spurious `METADATA_ONLY` entries** on files whose mtime was not
    preserved by unsquashfs. Stock unsquashfs on some systems does not
    restore the original file mtime for regular files (especially
    libraries, config files, and non-hardlinked binaries), stamping
    them with the extraction time instead. The tool correctly detects
    this as a metadata change, but the difference is harmless -- the
    repacker still reuses the original compressed data blocks verbatim,
    only the inode record (mtime field) is rewritten. To avoid this
    entirely, use `sqpack --reconstruct` instead of unsquashfs:
    it preserves mtime, mode, uid/gid, and hardlinks faithfully, and
    the round-trip produces byte-identical output (verified by
    `--self-test`).
  - Directory entries are written one-header-per-entry rather than
    mksquashfs's grouped-by-block layout -- fully spec-valid, just
    slightly less space-efficient (a few bytes per entry).

## Project structure

```
sqpack.py                  # standalone launcher -- `python3 sqpack.py ...` from anywhere
pyproject.toml             # `pip install .` exposes the `sqpack` command
sqfs_repacker/
  sqpack.py                 # dispatcher: operations -> phases, incl. --source-dir wiring
  cli.py                     # old per-phase CLI, unchanged, still usable directly
  constants.py, superblock.py, layout.py, toolcheck.py       # Phase 1
  analyzer.py
  compressor.py, metadata_reader.py, inode_structs.py,
  inode_parser.py, directory_parser.py, tables.py, tree.py    # Phase 2
  reconstruct.py                                               # + hardlink/mtime/mode preservation
  directory_diff.py                                            # NEW -- comparison only, no rebuilding
  encoder.py, table_builder.py                                 # Phase 3
  repacker.py                                                   # shared rebuild engine (--patch AND --source-dir)
  compare.py                                                    # Phase 4
```

## Phase roadmap

**Phase 1 -- Analyzer.** Done.
**Phase 2 -- Metadata reconstruction.** Done (now with mtime/mode/hardlink-preserving extraction, and real mknod when running as root).
**Phase 3 -- Deterministic repacker.** Done -- single shared engine for `--patch` and `--source-dir`.
**Phase 4 -- Validation / comparison.** Done.
**Unified CLI (`sqpack`).** Done, with `--self-test` and `--diff-detail`.

Natural next steps if useful: `EXTENDED_DIR`/export-table support, and
a way to express hardlink grouping explicitly for `--patch`-only
workflows (today it's automatic only for `--source-dir`).

## License

Standard copyright notice, © 2026 Bharatiy, "All Rights Reserved".
See `LICENSE` for full terms.
