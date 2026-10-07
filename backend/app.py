"""The FastAPI application: middleware, routers and the built frontend."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from backend import admin, auth, reports
from backend.cli import bootstrap_admin
from backend.config import ROOT, settings
from backend.db import init_db
from backend.tools import TOOLS

FRONTEND_DIST = ROOT / "frontend" / "dist"

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
    "base-uri 'self'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def startup() -> None:
    """Everything the app needs before the first request. Safe to call more than once.

    uvicorn runs it through `lifespan`; passenger_wsgi.py calls it directly because
    the WSGI adapter used on cPanel doesn't run lifespan events.
    """
    init_db()
    bootstrap_admin()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    startup()
    yield


app = FastAPI(
    title="Sentinel Lite",
    lifespan=lifespan,
    # The interactive API docs are handy while developing but not needed in production.
    docs_url=None if settings.is_prod else "/api/docs",
    redoc_url=None,
    openapi_url=None if settings.is_prod else "/api/openapi.json",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="sentinel_session",
    max_age=8 * 60 * 60,  # 8 hours, then log in again
    same_site="lax",  # not sent on cross-site POSTs, which blocks CSRF
    https_only=settings.is_prod,  # the Secure flag; dev runs on plain http://localhost
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Sentinel checks other sites for these headers, so it sends them too."""
    response = await call_next(request)
    headers = dict(SECURITY_HEADERS)
    if request.url.path.startswith("/api/docs"):
        # The API docs page loads Swagger UI from a CDN, which our CSP would block.
        # That page only exists in development (it is switched off in production).
        del headers["Content-Security-Policy"]
    for name, value in headers.items():
        response.headers.setdefault(name, value)
    if settings.is_prod:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(reports.router)
for tool in TOOLS.values():
    app.include_router(tool.router, prefix="/api/tools", tags=["tools"])


@app.get("/api/health")
def health():
    return {"status": "ok"}


# --- The React app (built by `npm run build` into frontend/dist) ---

if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def frontend(path: str):
    """Serve index.html for every non-API path so React Router can handle the URL."""
    if path.startswith("api/"):
        raise HTTPException(404, "Not found")
    index = FRONTEND_DIST / "index.html"
    if not index.is_file():
        return PlainTextResponse("Frontend not built yet. Run: python run.py", status_code=503)
    return FileResponse(index)
