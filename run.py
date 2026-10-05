#!/usr/bin/env python3
"""Start Sentinel Lite with one command:  python run.py

1. Creates .env with a random SECRET_KEY if it doesn't exist.
2. Creates a virtual environment in .venv and installs the Python packages
   (again only when requirements change).
3. Builds the React frontend if it is missing or out of date (needs Node.js).
4. Asks for the first admin account if there is none.
5. Starts the server on http://127.0.0.1:8000 and opens the browser.

    python run.py --no-browser     same, without opening the browser

This is one of the two files allowed to start other programs (see CLAUDE.md):
it runs pip and npm, always with an argument list and never through a shell.
"""

import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import threading
import venv
import webbrowser
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("Sentinel Lite needs Python 3.11 or newer.")

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
VENV_PYTHON = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
REQUIREMENTS = [ROOT / "requirements.txt", ROOT / "requirements-dev.txt"]
REQUIREMENTS_STAMP = VENV / "requirements.sha256"
FRONTEND = ROOT / "frontend"
HOST, PORT = "127.0.0.1", 8000


def run(command: list[str], cwd: Path = ROOT) -> None:
    print("  $ " + " ".join(command))
    subprocess.run(command, cwd=cwd, check=True)


def ensure_env_file() -> None:
    env_file = ROOT / ".env"
    if env_file.exists():
        return
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    text = text.replace("SECRET_KEY=CHANGE_ME", "SECRET_KEY=" + secrets.token_urlsafe(48))
    env_file.write_text(text, encoding="utf-8")
    print("Created .env with a random SECRET_KEY.")


def ensure_venv() -> None:
    if not VENV_PYTHON.exists():
        print("Creating a virtual environment in .venv ...")
        venv.create(VENV, with_pip=True)
    wanted = hashlib.sha256(b"".join(path.read_bytes() for path in REQUIREMENTS)).hexdigest()
    if REQUIREMENTS_STAMP.exists() and REQUIREMENTS_STAMP.read_text() == wanted:
        return
    print("Installing Python packages ...")
    run([str(VENV_PYTHON), "-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", "requirements-dev.txt"])
    REQUIREMENTS_STAMP.write_text(wanted)


def is_newer(paths: list[Path], than: Path) -> bool:
    return any(path.stat().st_mtime > than.stat().st_mtime for path in paths if path.is_file())


def build_frontend() -> None:
    index = FRONTEND / "dist" / "index.html"
    sources = [*(FRONTEND / "src").rglob("*"), FRONTEND / "index.html", FRONTEND / "vite.config.js"]
    if index.exists() and not is_newer(sources, index):
        return
    npm = shutil.which("npm")
    if npm is None:
        sys.exit("Building the frontend needs Node.js 20 or newer: https://nodejs.org (then run again).")
    print("Building the frontend ...")
    installed = FRONTEND / "node_modules" / ".package-lock.json"
    if not installed.exists() or is_newer([FRONTEND / "package-lock.json"], installed):
        run([npm, "ci", "--no-audit", "--no-fund"], cwd=FRONTEND)
    run([npm, "run", "build"], cwd=FRONTEND)


def start_server(open_browser: bool) -> None:
    """Runs inside the virtual environment, where the backend's packages are installed."""
    import uvicorn

    from backend.cli import admin_exists, create_admin
    from backend.db import init_db

    init_db()
    if not admin_exists():
        print("\nNo admin account yet. Create one now:")
        try:
            create_admin()
        except EOFError:  # no keyboard attached, e.g. started by a script
            print("\nSkipped. Create the admin later with: python -m backend.cli create-admin")

    url = f"http://{HOST}:{PORT}"
    print(f"\nSentinel Lite is running at {url}  (press Ctrl+C to stop)\n")
    if open_browser:
        threading.Timer(1.5, webbrowser.open, args=[url]).start()
    uvicorn.run("backend.app:app", host=HOST, port=PORT)


def main() -> None:
    open_browser = "--no-browser" not in sys.argv
    in_venv = Path(sys.prefix).resolve() == VENV.resolve()
    try:
        if in_venv:
            start_server(open_browser)
            return
        ensure_env_file()
        ensure_venv()
        build_frontend()
        # Start this script again with the virtual environment's Python.
        result = subprocess.run([str(VENV_PYTHON), str(ROOT / "run.py"), *sys.argv[1:]], cwd=ROOT)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\nStopped.")
    except subprocess.CalledProcessError as error:
        sys.exit(f"A setup step failed (exit code {error.returncode}). See the messages above.")


if __name__ == "__main__":
    main()
