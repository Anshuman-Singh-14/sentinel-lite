"""SQLite connection. Tables are created on startup; there are no migrations."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.config import settings

# check_same_thread=False: FastAPI may use a session from a different worker thread
# than the one that opened the connection. Each request still gets its own session.
engine = create_engine(f"sqlite:///{settings.db_file}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    """Create the database folder and any missing tables. Safe to call more than once."""
    import backend.models  # noqa: F401  (registers the tables on Base)

    settings.db_file.parent.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(engine)


def get_db():
    """FastAPI dependency: one database session per request."""
    with SessionLocal() as db:
        yield db
