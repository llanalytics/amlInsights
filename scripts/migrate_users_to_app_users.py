#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

# Add parent directory to path so we can import project modules.
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

sys.path.insert(0, PROJECT_ROOT)

from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from database import SessionLocal
from models import User
from platform_models import AppUser


def main() -> int:
    session = SessionLocal()
    migrated = 0
    skipped = 0
    now = datetime.now(timezone.utc)

    try:
        legacy_users = session.query(User).order_by(User.id.asc()).all()
        if not legacy_users:
            print("No legacy users found.")
            return 0

        for legacy in legacy_users:
            login_id = (legacy.username or "").strip().lower()
            if not login_id:
                skipped += 1
                continue

            existing = session.query(AppUser).filter(func.lower(AppUser.email) == login_id).first()
            if existing:
                if not existing.password_hash:
                    existing.password_hash = legacy.password_hash
                    if not existing.status:
                        existing.status = "active"
                    migrated += 1
                else:
                    skipped += 1
                continue

            session.add(
                AppUser(
                    email=login_id,
                    password_hash=legacy.password_hash,
                    status="active",
                    created_at=now,
                )
            )
            migrated += 1

        session.commit()
        print("Legacy user migration complete.")
        print(f"  migrated={migrated}")
        print(f"  skipped={skipped}")
        return 0
    except SQLAlchemyError as exc:
        session.rollback()
        print(f"Database error: {exc}")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
