"""
sqpack.py (package-internal implementation)
============================================
Unified CLI dispatcher for sqfs-repacker. This is the ONLY file end
users are meant to think about; Phases 1-4 (analyzer.py, reconstruct.py,
repacker.py, compare.py) remain exactly as they were -- this module
calls them, in the right order, and manages the intermediate artifacts
so the user operates in terms of OPERATIONS (analyze / reconstruct /
repack / compare / verify), never phases.

Design note on "automatic phase dependency resolution": --repack and
--verify do NOT need Phase 2's on-disk extraction step at all --
repacker.Repacker already consumes a parsed FilesystemImage/tree
in-memory (that IS Phase 1 + Phase 2's parsing, just not written to
disk as files). So for those two operations, "running Phase 2" means
building the tree in memory, not producing a squashfs-root/ directory
nobody asked for. --reconstruct is the one operation where Phase 2's
disk extraction is the actual deliverable, so it always writes real
files. This is a deliberate efficiency choice, not a shortcut -- see
the NOTES section of --help.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from typing import Dict, List, Optional

from . import analyzer
from . import constants
from . import reconstruct as reconstruct_mod
from . import repacker as repacker_mod
from . import compare as compare_mod
from .directory_diff import DirectoryDiffError
from .tree import FilesystemImage

PROG = "sqpack"
VERSION = "1.12.1"


# =========================================================================
# Help text -- traditional UNIX man-page-style sections, not argparse's
# default two-column dump. Triggered by -h, --help, ?, or no arguments.
# =========================================================================
HELP_TEXT = f"""\
NAME
    {PROG} -- deterministic SquashFS analysis, extraction, and repacking

SYNOPSIS
    mksquashfs-style (v1.4+ -- preferred for repacking edited trees):
        {PROG} [-s SOURCE_IMAGE] DIR [OUTPUT]

    Traditional (v1.3-compatible):
        {PROG} IMAGE --analyze [OUTPUT OPTIONS]
        {PROG} IMAGE --reconstruct [--extract DIR] [OUTPUT OPTIONS]
        {PROG} IMAGE --repack OUTPUT --patch IN=LOCAL [--patch IN=LOCAL ...] [OUTPUT OPTIONS]
        {PROG} IMAGE --repack OUTPUT --source-dir DIR [OUTPUT OPTIONS]
        {PROG} IMAGE --repack OUTPUT [OUTPUT OPTIONS]        (identity repack, no changes)
        {PROG} IMAGE --compare OTHER [OUTPUT OPTIONS]
        {PROG} IMAGE --verify [--patch IN=LOCAL ...] [--source-dir DIR] [OUTPUT OPTIONS]
        {PROG} IMAGE --self-test
        {PROG} -h | --help | ?

SHORT FLAGS (v1.4+)
    -a  --analyze           Analyze image, report reproducibility verdict
    -R  --reconstruct       Extract full tree to DIR (preserves mtime/mode/links)
    -r  --repack OUTPUT     Build new image (identity if no -d/-p; patched if given)
    -c  --compare OTHER     Compare two images
        --verify             Repack to temp, compare against original, discard
    -t  --self-test         Identity round-trip test (byte-identical check)
    -d  --source-dir DIR    Use DIR's diff against image as patch source
    -s  --source IMAGE      Source image for dir-first mode (overrides sidecar)
    -p  --patch [IN=]LOCAL  Replace IN with LOCAL's content (repeatable)
    -x  --extract DIR       Extraction destination (with -R)
    -o  --output FILE       Explicit output path (verify/repack)
    -k  --keep-temp         Don't delete temp files
    -n  --analysis-dir DIR  Persist Phase 1 artifacts
    -m  --manifest FILE     Persist Phase 2 manifest (with -R)
    -j  --json FILE         Write JSON report
    -l  --log FILE          Write human-readable forensic log
    -C  --compression ALGO  Force output codec: gzip|lzma|xz (--repack only)
    -v  --version           Print version and exit
    -V  --verbose           Increase verbosity (repeat for more: -VV)
    -q  --quiet             Suppress non-error output

DESCRIPTION
    sqpack is the single entry point for the sqfs-repacker toolkit. The
    toolkit is internally organized into four phases (analysis, metadata
    reconstruction, deterministic repacking, and comparison/validation),
    but these are implementation details -- sqpack determines which
    phases an operation needs and runs them automatically, in order.
    You never invoke a phase directly.

    All operations take a primary IMAGE as the first (positional)
    argument. --compare takes a second image as its argument (the file
    to compare IMAGE against); --repack takes its output path as its
    argument.

OPERATIONS
    --analyze
        Read-only forensic analysis of IMAGE: superblock, compression,
        flags, table layout, integrity findings. Runs Phase 1 only.

    --reconstruct
        Parse the full inode/directory tree and extract every file's
        real content to disk. Runs Phase 1 then Phase 2. Extraction
        directory defaults to "<image>.extracted" unless --extract is
        given. The result is immediately usable, unmodified, as a later
        --source-dir -- edit it in place, then --repack against it.

    --repack OUTPUT
        Rebuild IMAGE into OUTPUT. Three ways to say what changed,
        which can be combined:
          * no --patch and no --source-dir: identity repack (OUTPUT is
            byte-identical to IMAGE).
          * --patch IN=LOCAL (repeatable): replace the content of
            specific paths.
          * --source-dir DIR: automatically diff DIR (typically a
            --reconstruct output, edited) against IMAGE and patch every
            added/modified/removed/metadata-changed path -- no need to
            enumerate changes by hand, even across hundreds of
            thousands of files. If BOTH --source-dir and --patch are
            given, the directory scan is applied first and --patch is
            applied on top, winning on any path both mention.
        Only what actually changed is recompressed; everything else
        (including deduplicated/hardlinked content) is reused
        byte-for-byte from the original. Runs Phase 1, Phase 2 (in
        memory), and Phase 3.

    --compare OTHER
        Structured diff between IMAGE and OTHER: size, hashes,
        superblock fields, table layout, fragment content, and a full
        per-file tree diff. Runs Phase 4 only -- does not require IMAGE
        and OTHER to be related by a previous --repack.

    --verify
        Repack IMAGE (with --patch and/or --source-dir, or an identity
        repack if neither is given) to a temporary or explicit output,
        then immediately compare the result against IMAGE. Runs Phases
        1 through 4 in one command.

    --self-test
        One-command round-trip sanity check: extract IMAGE, rebuild it
        from that extraction with zero edits, and confirm the result is
        byte-identical to IMAGE. Prints PASS or FAIL with size/SHA-256
        detail either way, and exits 0 on PASS / 1 on FAIL -- a single,
        scriptable answer to "does sqpack actually handle my file
        correctly", without needing to run --reconstruct/--repack/
        --compare by hand.

OPTIONS
    -h, --help, ?
        Show this help and exit.

    -v, --version
        Print version and exit.

    -V, --verbose
        Print the full human-readable forensic log for each phase run,
        not just the summary. With --source-dir, also prints one line
        per changed path: "MODIFIED /etc/issue", "ADDED /etc/new.txt",
        "REMOVED /etc/old.txt", "METADATA_ONLY /etc/shadow", etc.
        Unchanged paths are summarized as a count, not listed
        individually.

    -q, --quiet
        Suppress all non-error console output; only exit status and
        (if requested) --json/--log files are produced. Errors always
        print to stderr regardless of -q.

PATCH OPTIONS
    --patch [IN_IMAGE_PATH=]LOCAL_FILE
        Replace the content of IN_IMAGE_PATH (a path inside the image,
        e.g. /etc/issue) with the contents of LOCAL_FILE. Repeatable --
        pass multiple --patch options to change several files in one
        run. Valid with --repack and --verify only. If the same path is
        also covered by --source-dir's automatic diff, --patch wins.

        Convenience form: --patch LOCAL_FILE (no "=" part). The in-image
        path is auto-derived by stripping any leading extract-dir prefix
        (squashfs-root/, <image>.extracted/, ./squashfs-root/, etc.) and
        prepending "/". So these are equivalent:

            --patch /etc/passwd.bak=./squashfs-root/etc/passwd.bak
            --patch ./squashfs-root/etc/passwd.bak
            --patch squashfs-root/etc/passwd.bak

        All three resolve to: in-image /etc/passwd.bak <- local file.

    --source-dir DIRECTORY
        Automatically diff DIRECTORY against IMAGE's original tree and
        patch every difference found: added files, removed files,
        modified content, and metadata-only changes (permissions,
        ownership, timestamps, symlink targets, device numbers) all
        require no manual enumeration. Hardlink topology is preserved:
        if two paths shared one inode originally and remain identical,
        they still share it; if only one changed, the shared inode is
        split so the unchanged path keeps reusing the original bytes;
        newly-added paths hardlinked to each other (or to an unchanged
        existing file) in DIRECTORY are recognized and merged rather
        than stored as duplicate content. Valid with --repack and
        --verify only. Comparison uses a fast path (size, mtime, mode)
        before falling back to hashing, so this scales to very large
        trees -- see NOTES.

OUTPUT OPTIONS
    --extract DIR
        Directory to extract file content into. Used by --reconstruct
        (default: "<image>.extracted"). Ignored by other operations,
        which do not produce an on-disk extraction (see NOTES).

    --output FILE
        Explicit path to save the rebuilt image produced by --verify.
        Without this, --verify builds to a temporary file and discards
        it after comparing (use --keep-temp to retain it anonymously,
        or --output to name it explicitly).

    --keep-temp
        Do not delete any automatically-created intermediate files
        (temporary output images, in-memory-only phases have nothing
        to keep, but this also disables cleanup of --verify's temp
        output when --output is not given).

    --analysis-dir DIR
        Persist Phase 1's analysis report/log into DIR instead of
        discarding them after use. Useful with --reconstruct, --repack,
        and --verify, where Phase 1 normally runs invisibly.

    --manifest FILE
        Persist Phase 2's full JSON metadata manifest to FILE. Only
        meaningful with --reconstruct (Phase 2 runs in-memory for
        --repack/--verify and has no manifest to save -- see NOTES).

    --json FILE
        Write the primary operation's structured JSON report to FILE
        (analysis report, reconstruction manifest, repack stats, or
        comparison report, depending on which operation was run).

    --preserve-timestamp
        Keep the original image's mkfs_time on a rebuilt superblock.
        This is the DEFAULT for --repack/--verify -- the flag exists to
        state the default explicitly, not to change it. (Earlier
        versions always stamped the current time on any rebuild with
        changes, which alone guaranteed the output could never hash-
        match the original even with byte-identical content; that was
        a bug, and preserving mkfs_time by default is the fix.)

    --new-timestamp UNIX_TIME
        Stamp the rebuilt superblock with this specific Unix timestamp
        instead of the original image's mkfs_time.

    --current-timestamp
        Stamp the rebuilt superblock with the current time (the OLD
        default behavior, still available if you specifically want a
        fresh timestamp on the rebuilt image).

COMPRESSION OVERRIDES
    -C ALGO, --compression ALGO
        Force the rebuilt image to use a different compression codec
        than the source. ALGO is one of: gzip, lzma, xz (these are the
        only algorithms the in-house encoder can currently write; lzo,
        lz4, zstd are accepted but will fail with a clear error if you
        actually try to write them). Examples:

          sqpack IMAGE -r OUT       # default: same codec as IMAGE
          sqpack IMAGE -r OUT -C xz    # force XZ output (e.g. LZMA -> XZ)
          sqpack IMAGE -r OUT -C lzma  # force LZMA output (e.g. XZ -> LZMA)
          sqpack IMAGE -r OUT -C gzip  # force zlib/gzip output

        What changes when you pass this flag:
          * superblock.compression field is rewritten to the new codec id
          * the COMPRESSOR_OPTIONS flag is set/cleared to match whether
            the new codec emits a comp_opts block (gzip/xz do; legacy
            LZMA does not)
          * the comp_opts block at offset 96 is regenerated (or removed)
            to match the new codec's expected on-disk format
          * the CompressorProfile fed to the encoder is rewritten so each
            metadata/data/fragment block is emitted in the new codec's
            native framing (e.g. XZ uses lzma.FORMAT_XZ, LZMA uses
            vendor5 5-byte header, gzip uses zlib level 9)

        This flag is mutually orthogonal to all patch/identity
        behaviour: -C xz with no -d/-p repacks the source tree as an
        identity rebuild but in the new codec; -C xz with -d DIR or -p
        applies your edits AND swaps the codec in one pass.

        Useful for cross-codec firmware conversions (e.g. an old LZMA
        firmware reissued as a smaller XZ one while keeping the same
        file tree), or for normalisation of a heterogeneous fleet onto
        one codec. There is no auto-pick-the-smallest mode -- if you
        want to compare sizes, repack twice and diff the byte counts.

LOGGING OPTIONS
    --log FILE
        Write the primary operation's full human-readable forensic log
        to FILE, regardless of -v/-q console verbosity.

EXAMPLES
    mksquashfs-style (v1.4+): extract, edit, repack -- source image is
    auto-detected from .sqpack_meta.json sidecar:
        {PROG} firmware.squashfs -R -x squashfs-root
        # edit anything under squashfs-root/
        {PROG} squashfs-root/                     # builds ./squashfs-root.squashfs

    Same, with explicit source and output paths:
        {PROG} -s firmware.squashfs squashfs-root/ patched.squashfs

    Analyze a firmware image:
        {PROG} firmware.squashfs --analyze

    Extract everything to squashfs-root/:
        {PROG} firmware.squashfs --reconstruct --extract squashfs-root

    Produce an identical copy (sanity check):
        {PROG} firmware.squashfs --repack copy.squashfs

    Patch a banner and a shadow file in one image:
        {PROG} firmware.squashfs --repack patched.squashfs \\
            --patch /etc/issue=new_issue.txt \\
            --patch /etc/shadow=new_shadow.txt

    Extract, edit by hand (add/remove/modify anything), then rebuild --
    no --patch flags needed, changes are detected automatically:
        {PROG} firmware.squashfs --reconstruct --extract squashfs-root
        $EDITOR squashfs-root/etc/issue
        rm squashfs-root/etc/old-service.conf
        echo hi > squashfs-root/etc/new-file.txt
        {PROG} firmware.squashfs --repack rebuilt.squashfs \\
            --source-dir squashfs-root

    Same, but override one specific file beyond what's in the tree:
        {PROG} firmware.squashfs --repack rebuilt.squashfs \\
            --source-dir squashfs-root \\
            --patch /etc/issue=one_more_change.txt

    Compare two arbitrary images:
        {PROG} original.squashfs --compare rebuilt.squashfs

    Patch and validate in one step, keeping the rebuilt image:
        {PROG} firmware.squashfs --verify \\
            --patch /etc/banner=new_banner \\
            --output firmware.patched.squashfs

    Directory-tree edit, validated in one step, with per-path logging:
        {PROG} firmware.squashfs --verify -V \\
            --source-dir squashfs-root --output firmware.patched.squashfs

EXIT STATUS
    0   operation completed successfully
    1   operation failed (parse error, I/O error, unsupported image, etc.)
    2   usage error (bad arguments, missing required option)

NOTES
    --repack and --verify do not write an intermediate extraction
    directory or Phase 2 manifest to disk by default: the repacker
    consumes Phase 1+2's parsed result directly from memory, since
    nothing downstream needs it as files. This is faster and avoids
    leaving artifacts you didn't ask for; pass --analysis-dir/--manifest
    if you specifically want those intermediate artifacts preserved
    for inspection.

    --source-dir comparison uses a fast path first (size + mtime + mode
    + type, no hashing) and only hashes file content when the fast path
    is ambiguous about whether it actually changed -- this is what
    makes it viable on trees with hundreds of thousands of files. One
    consequence: a file whose mtime and size both happen to match the
    original but whose CONTENT was silently changed (extremely unusual
    outside of deliberately adversarial edits) would be missed. This is
    the standard rsync-style quick-check trade-off, not an oversight.

    --source-dir only correctly detects hardlinks and device/fifo/
    socket "expected absence" if DIRECTORY came from THIS tool's own
    --reconstruct (which preserves hardlinks via os.link, and records
    which special nodes it couldn't create -- mknod needs root -- in a
    small `.sqpack_meta.json` sidecar file inside the extraction
    directory). Do not delete that sidecar file; it costs nothing to
    keep and --repack/--verify never treat it as part of the image.

    --source-dir with an unsquashfs-extracted tree may show spurious
    METADATA_ONLY entries on files whose mtime was not preserved by
    unsquashfs (some versions do not restore original mtimes for
    regular files). The repacker still reuses the original compressed
    data blocks verbatim -- only the inode mtime field is rewritten.
    To avoid these entries entirely, use --reconstruct instead of
    unsquashfs: it preserves mtime, mode, uid/gid, and hardlinks
    faithfully, and --self-test confirms byte-identical round-trips.

    Every phase remains independently usable by developers:
        python3 -m sqfs_repacker.cli analyze|reconstruct|repack|compare
    is still available and unaffected by sqpack -- see cli.py.
"""


# =========================================================================
# Temp/artifact management
# =========================================================================
class ArtifactManager:
    """Owns any temporary directory/files this run creates, and cleans
    them up on exit unless the user asked to keep them (--keep-temp) or
    gave an explicit persistent path for that artifact."""

    def __init__(self, keep_temp: bool):
        self.keep_temp = keep_temp
        self._tempdir: Optional[str] = None

    def tempdir(self) -> str:
        if self._tempdir is None:
            self._tempdir = tempfile.mkdtemp(prefix="sqpack_")
        return self._tempdir

    def temp_path(self, name: str) -> str:
        return os.path.join(self.tempdir(), name)

    def cleanup(self):
        if self._tempdir and not self.keep_temp and os.path.isdir(self._tempdir):
            shutil.rmtree(self._tempdir, ignore_errors=True)


def _log(args, msg: str, level: str = "info"):
    if args.quiet and level != "error":
        return
    stream = sys.stderr if level == "error" else sys.stdout
    print(msg, file=stream)


def _run_phase1(image: str, args, am: ArtifactManager) -> analyzer.AnalysisReport:
    report = analyzer.analyze(image)
    if args.verbose:
        _log(args, analyzer.format_forensic_log(report))
    if args.analysis_dir:
        os.makedirs(args.analysis_dir, exist_ok=True)
        with open(os.path.join(args.analysis_dir, "analysis.json"), "w") as f:
            f.write(report.to_json())
        with open(os.path.join(args.analysis_dir, "analysis.log"), "w") as f:
            f.write(analyzer.format_forensic_log(report))
    return report


class PatchSyntaxError(ValueError):
    pass


# Common extract-dir prefixes -- when --patch is given without "=", we strip
# any of these leading prefixes from the local path to derive the in-image
# path. Order matters: longest match first.
_EXTRACT_PREFIXES = (
    "squashfs-root-01/",
    "squashfs-root/",
    "squashfs-root",
    "squashfs.extracted/",
    "squashfs.extracted",
    "squashfs-reconstructed/",
    "squashfs-reconstructed",
    "extracted/",
    "extracted",
)


def _derive_in_image_path(local_path: str) -> str:
    """Convert a local file path into the in-image path it would have.

    Used when --patch is given without an explicit IN= prefix, so users
    can say --patch squashfs-root/etc/passwd.bak instead of
    --patch /etc/passwd.bak=squashfs-root/etc/passwd.bak.

    Strips any leading extract-dir prefix (./squashfs-root/, squashfs-root/,
    etc.) and ensures the result starts with '/'.
    """
    p = local_path
    # Strip leading ./
    while p.startswith("./"):
        p = p[2:]
    # Strip leading extract-dir prefix (longest match first)
    for prefix in _EXTRACT_PREFIXES:
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    # Ensure leading /
    if not p.startswith("/"):
        p = "/" + p
    return p


def _build_patches(patch_args: Optional[List[str]]) -> Dict[str, bytes]:
    patches: Dict[str, bytes] = {}
    for pair in (patch_args or []):
        if "=" in pair:
            in_path, local_path = pair.split("=", 1)
        else:
            # Bare local-path form: --patch PATH/TO/FILE
            # Auto-derive the in-image path by stripping common extract-dir
            # prefixes (squashfs-root/, <image>.extracted/, etc.).
            local_path = pair
            in_path = _derive_in_image_path(local_path)
        with open(local_path, "rb") as f:
            patches[in_path] = f.read()
    return patches


# =========================================================================
# Operations
# =========================================================================
def op_analyze(image: str, args, am: ArtifactManager) -> int:
    report = _run_phase1(image, args, am)
    if not args.verbose:
        _log(args, f"{image}: SquashFS {report.superblock.s_major}.{report.superblock.s_minor}, "
                    f"{report.superblock.compression_name}, {report.superblock.inodes} inodes, "
                    f"{report.file_size} bytes")
        _log(args, report.reproducibility_verdict)
    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
    if args.log:
        with open(args.log, "w") as f:
            f.write(analyzer.format_forensic_log(report))
    return 0


def op_reconstruct(image: str, args, am: ArtifactManager) -> int:
    _run_phase1(image, args, am)  # validate + optional --analysis-dir artifact

    extract_dir = args.extract or (os.path.basename(image) + ".extracted")
    report = reconstruct_mod.reconstruct(image, extract_dir=extract_dir, write_files=True)

    if args.verbose:
        _log(args, reconstruct_mod.format_forensic_log(report))
    else:
        _log(args, f"extracted {report.files_extracted} file(s) to {extract_dir} "
                    f"({len(report.files_failed)} failure(s))")

    if args.manifest:
        with open(args.manifest, "w") as f:
            f.write(report.to_json())
    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
    if args.log:
        with open(args.log, "w") as f:
            f.write(reconstruct_mod.format_forensic_log(report))

    return 0 if not report.files_failed else 1


def _do_repack(image: str, output: str, patches: Dict[str, bytes], source_dir: Optional[str],
                args, am: ArtifactManager) -> "repacker_mod.RepackStats":
    _run_phase1(image, args, am)  # Phase 1 diagnostics / optional --analysis-dir artifact

    fs = FilesystemImage(image)   # Phase 1 (superblock) + Phase 2 (tree), in memory
    fs.build_tree()

    if args.manifest:
        # The user explicitly asked for the Phase 2 manifest even though
        # repack doesn't need it internally -- produce it via reconstruct's
        # manifest builder without writing any file content to disk.
        root = fs.root
        with open(args.manifest, "w") as f:
            json.dump(root.to_manifest_dict(), f, indent=2)

    output_compression = getattr(args, "compression", None)

    if getattr(args, "current_timestamp", False):
        mkfs_time = None
    elif getattr(args, "new_timestamp", None) is not None:
        mkfs_time = args.new_timestamp
    else:
        mkfs_time = "preserve"  # default

    # --- Option A: --compression auto ---------------------------------
    # Try every codec, keep whichever produces the smallest rebuilt image.
    # SquashFS can only name ONE codec per image (in the superblock), so
    # even with auto we have to commit to a single codec -- but we get to
    # pick it based on actual compression results, not a heuristic.
    #
    # Implementation: run Repacker.build() once per codec, measure the
    # resulting byte length, keep the smallest. Costs ~3x build time but
    # zero changes to Repacker itself (which stays codec-agnostic).
    #
    # Only writable codecs are tried (gzip, lzma, xz). lz4, lzo, zstd
    # are accepted by --compression for clarity but raise a clear
    # error if actually attempted; skipping them here means -C auto
    # never crashes even if the user is on a build without those
    # encoders.
    if output_compression == "auto":
        writable = ("gzip", "lzma", "xz")
        # Detect source codec via the superblock (already parsed in fs).
        # When the source's codec matches a trial codec, identity bytes
        # are provably optimal (no re-encoding can beat the original for
        # the same codec) AND we avoid triggering known cross-codec bugs
        # like the legacy-LZMA end-marker mismatch.
        source_codec_id = getattr(getattr(fs, "sb", None), "compression", None)
        source_codec_name = None
        if source_codec_id is not None:
            for n, cid in constants.COMPRESSION_NAMES.items():
                if cid == source_codec_id and n in ("gzip", "lzma", "xz"):
                    source_codec_name = n
                    break
        best_bytes = None
        best_codec = None
        best_stats = None
        all_results = []  # (codec, size_or_None, error_str_or_None, stats)
        for trial_codec in writable:
            # Identity shortcut is only valid when there are no user
            # modifications to apply. If source_dir was provided the user
            # expects their changes to be reflected in EVERY codec trial,
            # so we must run the full Repacker.build() even when trial
            # codec matches source — otherwise modifications are silently
            # dropped from the winning output.
            if trial_codec == source_codec_name and not source_dir:
                # Identity is provably optimal AND avoids triggering the
                # legacy-LZMA end-marker bug when the source is LZMA.
                trial_bytes = fs.data
                trial_stats = repacker_mod.RepackStats(mode="identity")
                trial_stats.new_size = len(trial_bytes)
                trial_stats.original_size = len(trial_bytes)
                trial_stats.source_dir = source_dir
                trial_size = len(trial_bytes)
                trial_err = None
                all_results.append((trial_codec, trial_size, trial_err, trial_stats))
                if best_bytes is None or len(trial_bytes) < len(best_bytes):
                    best_bytes = trial_bytes
                    best_codec = trial_codec
                    best_stats = trial_stats
                continue
            rp = repacker_mod.Repacker(fs, output_compression=trial_codec)
            try:
                trial_bytes, trial_stats = rp.build(
                    patches or None, source_dir=source_dir, mkfs_time=mkfs_time,
                )
                trial_size = len(trial_bytes)
                trial_err = None
            except Exception as e:
                # A codec can fail (e.g. LZMA end-marker bug on already-XZ
                # source). Record the error and continue with next codec.
                trial_bytes = None
                trial_size = None
                trial_stats = None
                trial_err = str(e)
            all_results.append((trial_codec, trial_size, trial_err, trial_stats))
            if trial_bytes is not None and (best_bytes is None or len(trial_bytes) < len(best_bytes)):
                best_bytes = trial_bytes
                best_codec = trial_codec
                best_stats = trial_stats
        if best_bytes is None:
            err_lines = [f"  {c}: {err}" for c, _, err, _ in all_results]
            raise RuntimeError(
                f"--compression auto: every candidate codec failed.\n"
                + "\n".join(err_lines)
            )
        # Stash the auto-pick decision on the returned stats object so
        # downstream logging/printing can show "auto chose: lzma".
        if best_stats is not None and hasattr(best_stats, "auto_codec_results"):
            best_stats.auto_codec_results = all_results
            best_stats.auto_codec_winner = best_codec
        if not getattr(args, "quiet", False):
            print(f"[--compression auto] tried {len(writable)} codecs:",
                  file=sys.stderr)
            for trial_codec, trial_size, trial_err, _ in all_results:
                if trial_size is not None:
                    marker = " <- winner" if trial_codec == best_codec else ""
                    print(f"    {trial_codec:6s} -> {trial_size:>10d} bytes{marker}",
                          file=sys.stderr)
                else:
                    print(f"    {trial_codec:6s} -> FAILED ({trial_err[:60]}...)",
                          file=sys.stderr)
        with open(output, "wb") as f:
            f.write(best_bytes)
        return best_stats
    # ------------------------------------------------------------------

    rp = repacker_mod.Repacker(fs, output_compression=output_compression)
    new_bytes, stats = rp.build(patches or None, source_dir=source_dir, mkfs_time=mkfs_time)
    with open(output, "wb") as f:
        f.write(new_bytes)
    return stats


def _log_directory_diff(args, stats: "repacker_mod.RepackStats") -> None:
    """--source-dir verbose logging: one line per non-unchanged path, as
    'STATUS  /path' -- UNCHANGED/MODIFIED/ADDED/REMOVED/METADATA_ONLY.
    With --diff-detail [N], also prints up to N entries per status
    category (including a UNCHANGED sample) with their specific
    metadata_changes, so it's obvious exactly what was detected and why
    -- not just a count."""
    if stats.directory_diff and getattr(args, "diff_detail", None) is not None:
        n = args.diff_detail
        d = stats.directory_diff
        detail = d.get("entries_detail", {})
        by_status: Dict[str, List[str]] = {}
        for path, info in detail.items():
            by_status.setdefault(info["status"], []).append(path)
        for status in ("MODIFIED", "ADDED", "REMOVED", "METADATA_ONLY", "TYPE_CHANGED"):
            paths = sorted(by_status.get(status, []))
            if not paths:
                continue
            _log(args, f"-- {status} ({len(paths)} total, showing up to {n}) --")
            for path in paths[:n]:
                changes = detail.get(path, {}).get("metadata_changes", {})
                _log(args, f"  {path}" + (f"  {changes}" if changes else ""))
        unchanged_sample = d.get("unchanged_files", [])[:n]
        if unchanged_sample:
            _log(args, f"-- UNCHANGED ({d.get('unchanged_count', 0)} total, showing up to {n}) --")
            for path in unchanged_sample:
                _log(args, f"  {path}")
        return

    if not args.verbose or not stats.directory_diff:
        return
    d = stats.directory_diff
    for status_key, label in (("modified_files", "MODIFIED"), ("added_files", "ADDED"),
                               ("removed_files", "REMOVED"), ("metadata_only_changes", "METADATA_ONLY"),
                               ("changed_symlinks", "MODIFIED"), ("changed_devices", "MODIFIED"),
                               ("changed_fifos", "MODIFIED"), ("changed_sockets", "MODIFIED"),
                               ("changed_directories", "MODIFIED"), ("type_changed", "TYPE_CHANGED")):
        for path in d.get(status_key, []):
            _log(args, f"{label:<14}{path}")


def op_repack(image: str, args, am: ArtifactManager) -> int:
    patches = _build_patches(args.patch)
    stats = _do_repack(image, args.repack, patches, args.source_dir, args, am)

    _log_directory_diff(args, stats)
    log_text = repacker_mod.format_forensic_log(stats, image, args.repack)
    if args.verbose:
        _log(args, log_text)
    else:
        _log(args, f"{stats.mode}: {stats.files_reused_verbatim} reused, "
                    f"{stats.files_recompressed} recompressed -> {args.repack} "
                    f"({stats.new_size} bytes, {stats.new_size - stats.original_size:+d})")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(stats.to_dict(), f, indent=2)
    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)
    return 0


def op_compare(image: str, args, am: ArtifactManager) -> int:
    report = compare_mod.compare(image, args.compare)
    log_text = compare_mod.format_forensic_log(report)
    if args.verbose:
        _log(args, log_text)
    else:
        for line in report.summary:
            _log(args, f"* {line}")

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)
    return 0


def op_self_test(image: str, args, am: ArtifactManager) -> int:
    """Hardening: a one-command round-trip check anyone can run against
    their own image. Extracts, rebuilds from that extraction with zero
    edits, and compares against the original -- if this tool works
    correctly on THIS image, the result is always byte-identical. This
    exists so "does sqpack actually work on my file" has a single,
    unambiguous, scriptable answer instead of a multi-step manual check."""
    import hashlib
    extract_dir = am.temp_path("self_test_extracted")
    output = am.temp_path("self_test_rebuilt.squashfs")

    _log(args, f"[1/3] --reconstruct {image} -> {extract_dir}")
    recon_report = reconstruct_mod.reconstruct(image, extract_dir=extract_dir, write_files=True)
    if recon_report.files_failed:
        _log(args, f"FAIL: {len(recon_report.files_failed)} file(s) failed to extract", level="error")
        return 1

    _log(args, f"[2/3] --repack (from that extraction, no edits) -> {output}")
    fs = FilesystemImage(image)
    fs.build_tree()
    rp = repacker_mod.Repacker(fs, output_compression=getattr(args, "compression", None))
    new_bytes, stats = rp.build(source_dir=extract_dir)
    with open(output, "wb") as f:
        f.write(new_bytes)

    _log(args, f"[3/3] comparing {output} against {image}")
    with open(image, "rb") as f:
        original_bytes = f.read()
    original_sha = hashlib.sha256(original_bytes).hexdigest()
    rebuilt_sha = hashlib.sha256(new_bytes).hexdigest()
    identical = original_bytes == new_bytes

    result = {
        "image": os.path.abspath(image),
        "original_size": len(original_bytes),
        "rebuilt_size": len(new_bytes),
        "original_sha256": original_sha,
        "rebuilt_sha256": rebuilt_sha,
        "byte_identical": identical,
        "directory_diff_counts": stats.directory_diff and {
            k: v for k, v in stats.directory_diff.items()
            if k.endswith("_count")
        },
        "repack_mode": stats.mode,
    }

    if identical:
        _log(args, f"PASS: round-trip is byte-identical "
                    f"(size={len(original_bytes)}, sha256={original_sha[:16]}...)")
    else:
        _log(args, f"FAIL: round-trip is NOT byte-identical "
                    f"(original {len(original_bytes)} bytes / {original_sha[:16]}... vs "
                    f"rebuilt {len(new_bytes)} bytes / {rebuilt_sha[:16]}...)", level="error")
        if stats.directory_diff:
            _log(args, f"  directory diff counts: "
                        f"{ {k: v for k, v in stats.directory_diff.items() if k.endswith('_count')} }",
                 level="error")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
    if args.log:
        with open(args.log, "w") as f:
            f.write(repacker_mod.format_forensic_log(stats, image, output))

    return 0 if identical else 1


def op_verify(image: str, args, am: ArtifactManager) -> int:
    patches = _build_patches(args.patch)
    output = args.output or am.temp_path("verify_output.squashfs")

    stats = _do_repack(image, output, patches, args.source_dir, args, am)
    _log_directory_diff(args, stats)
    if args.verbose:
        _log(args, repacker_mod.format_forensic_log(stats, image, output))

    report = compare_mod.compare(image, output)
    log_text = compare_mod.format_forensic_log(report)
    if args.verbose:
        _log(args, log_text)
    else:
        for line in report.summary:
            _log(args, f"* {line}")

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)

    if args.output:
        _log(args, f"rebuilt image saved to {args.output}")
    elif args.keep_temp:
        _log(args, f"rebuilt image kept at {output}")

    return 0


# =========================================================================
# Argument parsing
# =========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=PROG, add_help=False)
    p.add_argument("image", nargs="?", help=argparse.SUPPRESS)
    p.add_argument("positional_output", nargs="?", help=argparse.SUPPRESS)

    # Operations -- every op gets a short alias
    ops = p.add_mutually_exclusive_group()
    ops.add_argument("-a", "--analyze", action="store_true")
    ops.add_argument("-R", "--reconstruct", action="store_true")
    ops.add_argument("-r", "--repack", metavar="OUTPUT")
    ops.add_argument("-c", "--compare", metavar="OTHER")
    ops.add_argument("--verify", action="store_true")
    ops.add_argument("-t", "--self-test", action="store_true", dest="self_test")

    # Patch / source-dir / source image
    p.add_argument("-p", "--patch", action="append", metavar="[IN=]LOCAL")
    p.add_argument("-d", "--source-dir", metavar="DIR", dest="source_dir")
    p.add_argument("-s", "--source", metavar="IMAGE", dest="source_image",
                   help="source image for dir-first repack (auto-detected from "
                        "sidecar or sibling if omitted)")

    # Output / extraction
    p.add_argument("-x", "--extract", metavar="DIR")
    p.add_argument("-o", "--output", metavar="FILE")
    p.add_argument("-k", "--keep-temp", action="store_true", dest="keep_temp")
    p.add_argument("-n", "--analysis-dir", metavar="DIR", dest="analysis_dir")
    p.add_argument("-m", "--manifest", metavar="FILE")
    p.add_argument("-j", "--json", metavar="FILE")
    p.add_argument("-l", "--log", metavar="FILE")

    # Timestamp
    ts_group = p.add_mutually_exclusive_group()
    ts_group.add_argument("--preserve-timestamp", action="store_true", dest="preserve_timestamp")
    ts_group.add_argument("--new-timestamp", type=int, metavar="UNIX_TIME", dest="new_timestamp")
    ts_group.add_argument("--current-timestamp", action="store_true", dest="current_timestamp")

    # Output codec (forces repack to write a different compression than the source).
    # Default (no flag) preserves the original compression, byte-identical.
    # Special value "auto" runs the build three times (once per codec)
    # and keeps whichever produces the smallest output. Implemented in
    # the CLI layer (_run_repack) -- Repacker itself stays codec-agnostic.
    p.add_argument("-C", "--compression", metavar="ALGO", dest="compression",
                   choices=sorted(list(constants.COMPRESSION_NAMES.keys()) + ["auto"]),
                   help="Force output codec: gzip|lzma|xz|auto. Without this "
                        "flag, the output uses the same codec as the source "
                        "(byte-identical round-trip). 'auto' tries every "
                        "supported codec, keeps whichever produces the "
                        "smallest rebuilt image (3x build time). When a "
                        "specific codec is given, the matching comp_opts "
                        "block is regenerated and the COMPRESSOR_OPTIONS "
                        "flag is realigned automatically.")

    # Logging / misc
    p.add_argument("-V", "--verbose", action="count", default=0, dest="verbose",
                   help="Increase verbosity (repeat for more: -VV)")
    p.add_argument("--diff-detail", type=int, nargs="?", const=10, default=None,
                   dest="diff_detail", metavar="N")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--version", action="store_true", dest="version",
                   help="Print version and exit")
    p.add_argument("-h", "--help", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if not argv or "?" in argv or "-h" in argv or "--help" in argv:
        print(HELP_TEXT)
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"{PROG} {VERSION}")
        return 0

    # Detect mksquashfs-style positional form: sqpack DIR [OUTPUT]
    # Detected when: args.image is a directory (not a .squashfs file),
    # and no explicit operation flag is set. Expands to:
    #   sqpack <source_image> --repack <OUTPUT> --source-dir <DIR>
    if args.image and not args.repack and not args.analyze and not args.reconstruct \
       and not args.compare and not args.verify and not args.self_test \
       and os.path.isdir(args.image):
        from .directory_diff import resolve_source_image
        dir_path = args.image
        output_path = args.positional_output
        if not output_path:
            # Default output: <basename(dir)>.squashfs in cwd (mksquashfs behavior)
            output_path = os.path.basename(os.path.abspath(dir_path)) + ".squashfs"
            if args.verbose:
                _log(args, f"no OUTPUT given, defaulting to {output_path!r}")

        # Trace sidecar detection (verbose only)
        if args.verbose:
            sidecar_path = os.path.join(os.path.abspath(dir_path), ".sqpack_meta.json")
            if os.path.isfile(sidecar_path):
                try:
                    with open(sidecar_path) as f:
                        _sc = json.load(f)
                    _log(args, f"[sidecar] reading {sidecar_path}")
                    _log(args, f"[sidecar] found -- source_image = {_sc.get('source_image', '?')!r}")
                except (OSError, ValueError):
                    _log(args, f"[sidecar] {sidecar_path} unreadable; falling back")
            else:
                _log(args, f"[sidecar] no sidecar at {sidecar_path}; will use sibling scan")

        # Resolve source image
        try:
            source = resolve_source_image(dir_path, explicit_source=args.source_image)
        except DirectoryDiffError as e:
            print(f"{PROG}: {e}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"{PROG}: cannot resolve source image: {e}", file=sys.stderr)
            return 2

        if args.verbose:
            _log(args, f"dir-first mode: source-dir  = {dir_path!r}")
            _log(args, f"                source-image= {source!r}")
            _log(args, f"                output      = {output_path!r}")

        args.image = source
        args.source_dir = dir_path
        args.repack = output_path

    if not args.image:
        print(f"{PROG}: missing IMAGE argument\nTry '{PROG} --help' for usage.", file=sys.stderr)
        return 2

    operation = None
    for name in ("analyze", "reconstruct", "repack", "compare", "verify", "self_test"):
        if getattr(args, name):
            operation = name
            break
    if operation is None:
        print(f"{PROG}: no operation given (--analyze/--reconstruct/--repack/--compare/--verify)\n"
              f"Try '{PROG} --help' for usage.", file=sys.stderr)
        return 2

    if args.patch and operation not in ("repack", "verify"):
        print(f"{PROG}: --patch is only valid with --repack or --verify", file=sys.stderr)
        return 2
    if args.source_dir and operation not in ("repack", "verify"):
        print(f"{PROG}: --source-dir is only valid with --repack or --verify", file=sys.stderr)
        return 2
    ts_flags_used = args.preserve_timestamp or args.new_timestamp is not None or args.current_timestamp
    if ts_flags_used and operation not in ("repack", "verify"):
        print(f"{PROG}: --preserve-timestamp/--new-timestamp/--current-timestamp are only "
              f"valid with --repack or --verify", file=sys.stderr)
        return 2

    args.verbose = bool(args.verbose)  # -V / -VV both just mean "verbose" for now
    am = ArtifactManager(keep_temp=args.keep_temp)

    dispatch = {
        "analyze": op_analyze,
        "reconstruct": op_reconstruct,
        "repack": op_repack,
        "compare": op_compare,
        "verify": op_verify,
        "self_test": op_self_test,
    }

    try:
        return dispatch[operation](args.image, args, am)
    except PatchSyntaxError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"{PROG}: error: {e}", file=sys.stderr)
        return 1
    finally:
        am.cleanup()


if __name__ == "__main__":
    sys.exit(main())
