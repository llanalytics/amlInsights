#!/usr/bin/env python3

import getpass
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_env_file() -> None:
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key or key in os.environ:
                continue
            value = value.strip()
            if (
                len(value) >= 2
                and ((value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"))
            ):
                value = value[1:-1]
            os.environ[key] = value


_load_env_file()

# Default to local DB for local workflows unless explicitly requested.
def _apply_database_target(target: str) -> None:
    selected = (target or "local").strip().lower()
    if selected not in {"local", "remote"}:
        raise ValueError("Target must be 'local' or 'remote'.")
    if selected == "local" and os.environ.get("LOCAL_DATABASE_URL"):
        os.environ["DATABASE_URL"] = os.environ["LOCAL_DATABASE_URL"]


# Apply target before importing database module.
if len(sys.argv) >= 3:
    _apply_database_target(sys.argv[2])
else:
    _apply_database_target("local")

# Add parent directory to path so we can import modules
sys.path.insert(0, PROJECT_ROOT)

from sqlalchemy.exc import OperationalError, ProgrammingError

from auth import hash_password
from database import SessionLocal
from platform_models import AppUser


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("Usage: python set_password.py <email_or_login_id> [local|remote]")
        return 1

    email = sys.argv[1].strip().lower()
    if not email:
        print("Email/login ID cannot be empty.")
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
        user = session.query(AppUser).filter(AppUser.email == email).first()
        if not user:
            print(f"User '{email}' does not exist.")
            return 1

        user.password_hash = hash_password(password)
        session.commit()
        print(f"Updated password for '{email}'.")
        return 0
    except (OperationalError, ProgrammingError) as exc:
        print("Database schema is not ready yet. Run `alembic upgrade head` first.")
        print(f"Details: {exc.__class__.__name__}")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
