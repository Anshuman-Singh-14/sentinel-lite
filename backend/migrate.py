"""Brings an existing database up to date with models.py.

create_all() makes missing tables but never adds columns to a table that already
exists, so new columns are added here with ALTER TABLE. Safe to run on every
startup: running it again changes nothing.
"""

from sqlalchemy import Engine, inspect

from backend.db import Base

# Column name -> SQL for ALTER TABLE. SQLite can't add a UNIQUE column, so the unique
# rule on email is a separate index (the same one create_all makes for a new database).
USER_COLUMNS = {
    "email": "VARCHAR(254)",
    "email_verified": "BOOLEAN NOT NULL DEFAULT 0",
    "must_change_password": "BOOLEAN NOT NULL DEFAULT 0",
    "display_name": "VARCHAR(50)",
}
ACTIVITY_COLUMNS = {
    "ip": "VARCHAR(45) NOT NULL DEFAULT '-'",
    "result": "VARCHAR(10) NOT NULL DEFAULT 'ok'",
}
# Targets that existed before private targets were added stay scannable by everyone.
ALLOWED_TARGET_COLUMNS = {
    "shared": "BOOLEAN NOT NULL DEFAULT 1",
}
COLUMNS = {"users": USER_COLUMNS, "activity": ACTIVITY_COLUMNS, "allowed_targets": ALLOWED_TARGET_COLUMNS}

# Before the ip column existed, logins kept the IP in the detail as "from 203.0.113.9".
BACKFILL_LOGIN_IPS = """
UPDATE activity SET ip = substr(detail, 6)
WHERE action IN ('login', 'login_failed') AND detail LIKE 'from %' AND detail NOT LIKE 'from % %'
"""


def migrate(engine: Engine) -> list[str]:
    """Create missing tables and columns. Returns what changed, e.g. ["added activity.ip"]."""
    import backend.models  # noqa: F401  (registers the tables on Base)

    changes = []
    existing_tables = set(inspect(engine).get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            changes.append(f"created table {table.name}")
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        for table, columns in COLUMNS.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            for name, sql_type in columns.items():
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
                    changes.append(f"added {table}.{name}")
        if "added activity.ip" in changes:
            filled = conn.exec_driver_sql(BACKFILL_LOGIN_IPS).rowcount
            if filled:
                changes.append(f"backfilled activity.ip for {filled} logins")
        conn.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)")
    return changes
