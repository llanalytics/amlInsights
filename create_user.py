#!/usr/bin/env python3

import getpass
import sys

from sqlalchemy.exc import OperationalError, ProgrammingError

from auth import hash_password
from database import SessionLocal
from models import User


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python create_user.py <username>")
        return 1

    username = sys.argv[1].strip()
    if not username:
        print("Username cannot be empty.")
        return 1

    password = getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Confirm password: ")

    if not password:
        print("Password cannot be empty.")
        return 1

    if password != password_confirm:
        print("Passwords do not match.")
        return 1

    session = SessionLocal()

    try:
        existing_user = session.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            return 1

        user = User(username=username, password_hash=hash_password(password))
        session.add(user)
        session.commit()
        print(f"Created user '{username}'.")
        return 0
    except (OperationalError, ProgrammingError) as exc:
        print("Database schema is not ready yet. Run `alembic upgrade head` first.")
        print(f"Details: {exc.__class__.__name__}")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
