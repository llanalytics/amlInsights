#!/usr/bin/env python3

import getpass
import sys
import os

# Add parent directory to path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.exc import OperationalError, ProgrammingError

from auth import hash_password
from database import SessionLocal
from models import User


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python set_password.py <username>")
        return 1

    username = sys.argv[1].strip()
    if not username:
        print("Username cannot be empty.")
        return 1

    password = getpass.getpass("New password: ")
    password_confirm = getpass.getpass("Confirm new password: ")

    if not password:
        print("Password cannot be empty.")
        return 1

    if password != password_confirm:
        print("Passwords do not match.")
        return 1

    session = SessionLocal()

    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"User '{username}' does not exist.")
            return 1

        user.password_hash = hash_password(password)
        session.commit()
        print(f"Updated password for '{username}'.")
        return 0
    except (OperationalError, ProgrammingError) as exc:
        print("Database schema is not ready yet. Run `alembic upgrade head` first.")
        print(f"Details: {exc.__class__.__name__}")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
