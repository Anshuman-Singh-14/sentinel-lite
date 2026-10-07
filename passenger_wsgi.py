"""Entry point for cPanel "Setup Python App" (Phusion Passenger). See DEPLOY-CPANEL.md.

Passenger only speaks WSGI, but our app is ASGI (FastAPI), so a2wsgi translates
between the two. a2wsgi doesn't run FastAPI's lifespan events, so the startup
work (database tables, first admin) is done here before the app is wrapped.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Passenger's current directory isn't guaranteed, so make `import backend` work from here.
sys.path.insert(0, str(ROOT))


def load_env_file(path: Path) -> None:
    """Copy KEY=value lines from .env into the environment. Variables set in cPanel win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


load_env_file(ROOT / ".env")

from a2wsgi import ASGIMiddleware  # noqa: E402

from backend.app import app, startup  # noqa: E402

startup()
application = ASGIMiddleware(app)
