"""Command line helpers.

    python -m backend.cli create-admin
    python -m backend.cli create-admin --username alice
"""

import argparse
import getpass

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import select

from backend.auth import hash_password
from backend.db import SessionLocal, init_db
from backend.models import User
from backend.validation import Password, Username


def admin_exists() -> bool:
    with SessionLocal() as db:
        return db.scalar(select(User).where(User.role == "admin")) is not None


def ask(adapter: TypeAdapter, prompt: str, secret: bool = False) -> str:
    """Prompt until the value passes the same validation the API uses."""
    while True:
        value = getpass.getpass(prompt) if secret else input(prompt)
        try:
            return adapter.validate_python(value)
        except ValidationError as error:
            print("  " + error.errors()[0]["msg"])


def create_admin(username: str | None = None) -> None:
    init_db()
    if username is None:
        username = ask(TypeAdapter(Username), "Admin username: ")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            print(f"User {username!r} already exists.")
            return
        while True:
            password = ask(TypeAdapter(Password), "Password (min 8 characters): ", secret=True)
            if getpass.getpass("Repeat password: ") == password:
                break
            print("  Passwords don't match, try again.")
        db.add(User(username=username, password_hash=hash_password(password), role="admin"))
        db.commit()
    print(f"Admin {username!r} created.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m backend.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-admin", help="create an admin user")
    create.add_argument("--username")
    args = parser.parse_args()
    if args.command == "create-admin":
        username = TypeAdapter(Username).validate_python(args.username) if args.username else None
        create_admin(username)


if __name__ == "__main__":
    main()
