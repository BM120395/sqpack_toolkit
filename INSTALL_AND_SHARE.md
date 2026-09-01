# sqpack_toolkit_v1 — install & share

The **complete, working** sqpack tool (v1.12.1) — the exact source that is
installed on PATH as `sqpack` (byte-identical to the uv-managed install under
`~/.local/share/uv/tools/sqfs-repacker/`).

## What's inside

```
sqpack_toolkit_v1/
├── sqpack.py                  # standalone launcher: `python3 sqpack.py ...` (no install needed)
├── pyproject.toml             # packaging: exposes the `sqpack` console command
├── README.md                  # full tool documentation (usage, install, project structure)
├── LICENSE                    # © 2026 Bharatiy — All Rights Reserved
├── dist/
│   ├── sqfs_repacker-1.12.1-py3-none-any.whl
│   └── sqfs_repacker-1.12.1.tar.gz
├── INSTALL_AND_SHARE.md       # this file
└── sqfs_repacker/             # the Python package (24 modules, phases 1–4 + unified CLI)
```

`sqfs_repacker/__init__.py` declares `__version__ = "1.12.1"`; the module set is
exactly the 24 shipped by the installed tool (verified byte-identical).

## Install as a tool (the way it's already installed here)

```sh
# On any machine with uv  — installs the `sqpack` command, isolated venv (Python 3.11)
uv tool install /path/to/sqpack_toolkit_v1

# …or from the built wheel
uv tool install ./dist/sqfs_repacker-1.12.1-py3-none-any.whl
```

The installed executable is `sqpack`:

```sh
$ sqpack --version
sqpack 1.12.1
```

Optional compression plugins: `uv tool install --with lz4 --with zstandard /path/to/sqpack_toolkit_v1`.

### Equivalent pip route (system/user venv)
```sh
pip install .                 # from inside sqpack_toolkit_v1/
pip install ./dist/sqfs_repacker-1.12.1-py3-none-any.whl
```

### No-install route (zero-dependency Python)
```sh
python3 sqpack.py --version
python3 sqpack.py IMAGE --analyze
```
The root `sqpack.py` launcher puts the package's parent dir on `sys.path`, so it
works from any working directory with just stdlib.

## Sharing with someone else
Zip the whole directory (or just hand them `dist/*.whl` + `README.md`):

```sh
cd ~/Scripts && zip -r sqpack_toolkit_v1.zip sqpack_toolkit_v1
```
Both the wheel (`sqfs_repacker-1.12.1-py3-none-any.whl`) and sdist
(`sqfs_repacker-1.12.1.tar.gz`) are built from this exact tree. This project is
not intended for public redistribution — see LICENSE (All Rights Reserved).

## Provenance
- Source of truth: `~/Scripts/sqfs_repacker_v1.12.1/sqfs_repacker/` (git-clean,
  3 commits). This kit is a byte-identical, artifact-free copy of that gone
  through to the exact files the installed tool ships.
- Verified: standalone launcher runs, `sqpack --version` → 1.12.1, wheel+sdist
  build, and the tool re-installed cleanly from this directory.
