import sqlite3

import pytest
from sqlalchemy import create_engine

from backend.migrate import migrate

# The database as it was before email and must_change_password existed.
OLD_SCHEMA = """
CREATE TABLE users (
    id INTEGER NOT NULL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    role VARCHAR(10) NOT NULL,
    is_active BOOLEAN NOT NULL,
    created_at DATETIME NOT NULL
);
CREATE TABLE scans (
    id INTEGER NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id),
    tool VARCHAR(32) NOT NULL,
    target VARCHAR(253) NOT NULL,
    summary JSON NOT NULL,
    findings JSON NOT NULL,
    created_at DATETIME NOT NULL
);
CREATE TABLE activity (
    id INTEGER NOT NULL PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    action VARCHAR(50) NOT NULL,
    detail VARCHAR(300) NOT NULL,
    created_at DATETIME NOT NULL
);
INSERT INTO users VALUES (1, 'admin', 'not-a-real-hash', 'admin', 1, '2026-10-01 10:00:00');
INSERT INTO scans VALUES (1, 1, 'dns_check', 'example.com', '{}', '[]', '2026-10-01 10:05:00');
INSERT INTO activity VALUES (1, 'admin', 'login', 'from 127.0.0.1', '2026-10-01 10:00:00');
"""


def schema(path) -> tuple[dict, list]:
    conn = sqlite3.connect(path)
    tables = {
        name: [row[1:3] for row in conn.execute(f"PRAGMA table_info({name})")]
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    indexes = sorted(conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'index'"))
    conn.close()
    return tables, indexes


def test_migration_upgrades_an_old_database_and_keeps_its_rows(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    conn.close()
    engine = create_engine(f"sqlite:///{path}")

    migrate(engine)
    after_first = schema(path)
    migrate(engine)  # a second run must change nothing
    engine.dispose()
    assert schema(path) == after_first

    tables, indexes = after_first
    assert {"access_requests", "email_tokens"} <= tables.keys()
    assert [name for name, _type in tables["users"]][-3:] == ["email", "email_verified", "must_change_password"]
    assert "ix_users_email" in [name for name, _sql in indexes]

    conn = sqlite3.connect(path)
    assert conn.execute("SELECT username, email, email_verified, must_change_password FROM users").fetchall() == [
        ("admin", None, 0, 0)
    ]
    assert conn.execute("SELECT target FROM scans").fetchall() == [("example.com",)]
    assert conn.execute("SELECT action FROM activity").fetchall() == [("login",)]
    # Many users may have no email, but two can't share one.
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'h', 'user', 1, '2026-10-02', NULL, 0, 0)")
    conn.execute("INSERT INTO users VALUES (3, 'eve', 'h', 'user', 1, '2026-10-02', 'e@x.com', 0, 0)")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO users VALUES (4, 'mal', 'h', 'user', 1, '2026-10-02', 'e@x.com', 0, 0)")
    conn.close()
