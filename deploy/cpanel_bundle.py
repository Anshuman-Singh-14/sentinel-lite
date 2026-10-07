#!/usr/bin/env python3
"""Build the upload for cPanel shared hosting:  python deploy/cpanel_bundle.py

1. Builds the React frontend (the server has no Node.js, so frontend/dist is shipped).
2. Zips the project into sentinel-lite-cpanel.zip in the repo root.

The zip leaves out secrets (.env), local data (*.db, data/), the virtual environment,
node_modules, caches and tests. See DEPLOY-CPANEL.md for what to do with it.

Like run.py, this file starts npm with an argument list and never through a shell
(see CLAUDE.md). shutil.which finds npm.cmd on Windows.
"""

import fnmatch
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
ZIP_PATH = ROOT / "sentinel-lite-cpanel.zip"

# Folders skipped wherever they appear.
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
# Folders skipped only at the top of the project.
SKIP_TOP_DIRS = {"data", "tests", ".github", ".claude"}
# File name patterns that never go in the upload.
SKIP_FILES = [".env", "*.db", "*.sqlite3", "*.pyc", "*.zip", "*.rar", "*.log"]


def build_frontend() -> None:
    npm = shutil.which("npm")
    if npm is None:
        sys.exit("Building the frontend needs Node.js 20 or newer: https://nodejs.org")
    for command in ([npm, "ci", "--no-audit", "--no-fund"], [npm, "run", "build"]):
        print("  $ npm " + " ".join(command[1:]))
        subprocess.run(command, cwd=FRONTEND, check=True)
    if not (FRONTEND / "dist" / "index.html").is_file():
        sys.exit("The build finished but frontend/dist/index.html is missing.")


def project_files():
    for folder, dirs, files in os.walk(ROOT):
        here = Path(folder)
        at_top = here == ROOT
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (at_top and d in SKIP_TOP_DIRS))
        for name in sorted(files):
            if not any(fnmatch.fnmatch(name, pattern) for pattern in SKIP_FILES):
                yield here / name


def make_zip() -> int:
    count = 0
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in project_files():
            # as_posix(): forward slashes, so the zip extracts into folders on Linux.
            archive.write(path, path.relative_to(ROOT).as_posix())
            count += 1
    return count


def main() -> None:
    print("Building the frontend ...")
    try:
        build_frontend()
    except subprocess.CalledProcessError as error:
        sys.exit(f"npm failed (exit code {error.returncode}). See the messages above.")
    print("Creating the zip ...")
    count = make_zip()
    size_mb = ZIP_PATH.stat().st_size / 1_000_000
    print(f"Done: {ZIP_PATH.name} ({count} files, {size_mb:.1f} MB). Next steps: DEPLOY-CPANEL.md")


if __name__ == "__main__":
    main()
