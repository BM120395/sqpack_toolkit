"""
cli.py
======
Command-line entry point.

Currently implements Phase 1:
    sqfs-repacker analyze <image> [--json report.json] [--log report.log]

Later phases (metadata reconstruction, deterministic repack, validation)
will add `reconstruct`, `repack`, and `compare` subcommands to this same
parser, reusing the library modules -- the CLI is intentionally a thin
wrapper so every capability is also usable programmatically.
"""

from __future__ import annotations

import argparse
import sys

from . import analyzer
from . import reconstruct as reconstruct_mod
from . import repacker as repacker_mod
from . import compare as compare_mod
from .tree import FilesystemImage


def cmd_analyze(args: argparse.Namespace) -> int:
    report = analyzer.analyze(args.image)
    log_text = analyzer.format_forensic_log(report)

    print(log_text)

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
        print(f"\n[+] JSON report written to {args.json}")

    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)
        print(f"[+] Forensic log written to {args.log}")

    return 0


def cmd_reconstruct(args: argparse.Namespace) -> int:
    report = reconstruct_mod.reconstruct(args.image, extract_dir=args.extract, write_files=not args.no_extract)
    log_text = reconstruct_mod.format_forensic_log(report)
    print(log_text)

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
        print(f"\n[+] JSON manifest written to {args.json}")

    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)
        print(f"[+] Forensic log written to {args.log}")

    return 0 if not report.files_failed else 1


def cmd_repack(args: argparse.Namespace) -> int:
    import json
    patches = {}
    if args.patch:
        for pair in args.patch:
            if "=" not in pair:
                print(f"[!] --patch expects IN_IMAGE_PATH=LOCAL_FILE, got: {pair}")
                return 2
            in_path, local_path = pair.split("=", 1)
            with open(local_path, "rb") as f:
                patches[in_path] = f.read()
    if args.patch_file:
        with open(args.patch_file, "rb") as f:
            patches[args.patch_path] = f.read()

    fs = FilesystemImage(args.image)
    fs.build_tree()
    rp = repacker_mod.Repacker(fs)

    if getattr(args, "current_timestamp", False):
        mkfs_time = None
    elif getattr(args, "new_timestamp", None) is not None:
        mkfs_time = args.new_timestamp
    else:
        mkfs_time = "preserve"  # default: keep the original image's mkfs_time

    new_bytes, stats = rp.build(patches or None, source_dir=args.source_dir, mkfs_time=mkfs_time)

    with open(args.output, "wb") as f:
        f.write(new_bytes)

    log_text = repacker_mod.format_forensic_log(stats, args.image, args.output)
    print(log_text)
    print(f"\n[+] Wrote {len(new_bytes)} bytes to {args.output}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(stats.to_dict(), f, indent=2)
        print(f"[+] JSON stats written to {args.json}")
    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)
        print(f"[+] Forensic log written to {args.log}")

    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    report = compare_mod.compare(args.original, args.rebuilt)
    log_text = compare_mod.format_forensic_log(report)
    print(log_text)

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
        print(f"\n[+] JSON report written to {args.json}")
    if args.log:
        with open(args.log, "w") as f:
            f.write(log_text)
        print(f"[+] Forensic log written to {args.log}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sqfs-repacker",
        description="Deterministic SquashFS analysis / repacking toolkit.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Phase 1: read-only forensic analysis of a SquashFS image")
    p_analyze.add_argument("image", help="Path to the SquashFS image")
    p_analyze.add_argument("--json", metavar="PATH", help="Write the full JSON report to PATH")
    p_analyze.add_argument("--log", metavar="PATH", help="Write the human-readable forensic log to PATH")
    p_analyze.set_defaults(func=cmd_analyze)

    p_recon = sub.add_parser("reconstruct", help="Phase 2: parse full metadata tree and extract file content")
    p_recon.add_argument("image", help="Path to the SquashFS image")
    p_recon.add_argument("--extract", metavar="DIR", help="Directory to extract real file content into")
    p_recon.add_argument("--no-extract", action="store_true", help="Parse only, do not write files to disk")
    p_recon.add_argument("--json", metavar="PATH", help="Write the full JSON manifest to PATH")
    p_recon.add_argument("--log", metavar="PATH", help="Write the human-readable forensic log to PATH")
    p_recon.set_defaults(func=cmd_reconstruct)

    p_repack = sub.add_parser("repack", help="Phase 3: rebuild the image, optionally patching one file's content")
    p_repack.add_argument("image", help="Path to the original SquashFS image")
    p_repack.add_argument("output", help="Path to write the rebuilt image to")
    p_repack.add_argument("--patch-path", help="(single-patch shortcut) In-image path of the file to replace")
    p_repack.add_argument("--patch-file", help="(single-patch shortcut) Local file whose content replaces --patch-path")
    p_repack.add_argument("--patch", action="append", metavar="IN_IMAGE_PATH=LOCAL_FILE",
                           help="Patch one file; repeat for multiple files, e.g. "
                                "--patch /etc/issue=new_issue.txt --patch /etc/shadow=new_shadow.txt")
    p_repack.add_argument("--source-dir", metavar="DIR",
                           help="Rebuild from a directory tree (e.g. produced by --reconstruct, then "
                                "edited): automatically diffs DIR against the original image and "
                                "patches every added/modified/removed/metadata-changed path. Combine "
                                "with --patch to apply explicit overrides on top (--patch wins).")
    p_repack.add_argument("--json", metavar="PATH", help="Write repack stats as JSON to PATH")
    p_repack.add_argument("--log", metavar="PATH", help="Write the human-readable forensic log to PATH")
    ts_group = p_repack.add_mutually_exclusive_group()
    ts_group.add_argument("--preserve-timestamp", action="store_true",
                           help="Keep the original image's mkfs_time (default behavior; this flag "
                                "exists to make the default explicit, not to change it)")
    ts_group.add_argument("--new-timestamp", type=int, metavar="UNIX_TIME",
                           help="Stamp the rebuilt superblock with this specific Unix timestamp "
                                "instead of the original's mkfs_time")
    ts_group.add_argument("--current-timestamp", action="store_true",
                           help="Stamp the rebuilt superblock with the current time (the OLD "
                                "default behavior, before mkfs_time preservation became the default)")
    p_repack.set_defaults(func=cmd_repack)

    p_compare = sub.add_parser("compare", help="Phase 4: validate/diff two SquashFS images")
    p_compare.add_argument("original", help="Path to the original SquashFS image")
    p_compare.add_argument("rebuilt", help="Path to the rebuilt/patched SquashFS image")
    p_compare.add_argument("--json", metavar="PATH", help="Write the full JSON diff report to PATH")
    p_compare.add_argument("--log", metavar="PATH", help="Write the human-readable forensic log to PATH")
    p_compare.set_defaults(func=cmd_compare)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
