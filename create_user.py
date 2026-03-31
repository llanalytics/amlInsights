#!/usr/bin/env python3

import getpass
import sys

from auth import hash_password
from database import SessionLocal, engine
from models import Base, User


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

    Base.metadata.create_all(bind=engine)
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
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
