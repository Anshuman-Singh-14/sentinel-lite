"""SQLite connection. Tables are created, and older databases upgraded, on startup (see migrate.py)."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.config import settings

# check_same_thread=False: FastAPI may use a session from a different worker thread
# than the one that opened the connection. Each request still gets its own session.
engine = create_engine(f"sqlite:///{settings.db_file}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> list[str]:
    """Create or upgrade the database. Returns what changed (see migrate.py)."""
    from backend.migrate import migrate

    return migrate(engine)


def get_db():
    """FastAPI dependency: one database session per request."""
    with SessionLocal() as db:
        yield db
