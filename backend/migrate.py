"""Brings an existing database up to date with models.py.

create_all() makes missing tables but never adds columns to a table that already
exists, so new columns on `users` are added here with ALTER TABLE. Safe to run on
every startup: running it again changes nothing.
"""

from sqlalchemy import Engine

from backend.db import Base

# Column name -> SQL for ALTER TABLE. SQLite can't add a UNIQUE column, so the unique
# rule on email is a separate index (the same one create_all makes for a new database).
USER_COLUMNS = {
    "email": "VARCHAR(254)",
    "email_verified": "BOOLEAN NOT NULL DEFAULT 0",
    "must_change_password": "BOOLEAN NOT NULL DEFAULT 0",
}


def migrate(engine: Engine) -> None:
    import backend.models  # noqa: F401  (registers the tables on Base)

    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(users)")}
        for name, sql_type in USER_COLUMNS.items():
            if name not in existing:
                conn.exec_driver_sql(f"ALTER TABLE users ADD COLUMN {name} {sql_type}")
        conn.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)")
