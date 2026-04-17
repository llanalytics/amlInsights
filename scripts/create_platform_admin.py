#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

# Add parent directory to path so we can import project modules and load .env first.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


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
if os.environ.get("LOCAL_DATABASE_URL") and os.environ.get("AML_TARGET", "local").strip().lower() == "local":
    os.environ["DATABASE_URL"] = os.environ["LOCAL_DATABASE_URL"]

from database import DATABASE_URL, DB_SCHEMA, SessionLocal, engine  # noqa: E402
from platform_models import AppUser, PlatformUserRole, Role  # noqa: E402


def table_exists(table_name: str) -> bool:
    insp = inspect(engine)
    try:
        return insp.has_table(table_name, schema=DB_SCHEMA)
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or update a platform admin user in auth_users/auth_platform_user_roles."
    )
    parser.add_argument("email", help="Admin email (must match x-user-email header value).")
    parser.add_argument(
        "--status",
        default="active",
        choices=["active", "inactive"],
        help="User status in auth_users (default: active).",
    )
    args = parser.parse_args()

    email = args.email.strip().lower()
    if not email:
        print("Email is required.")
        return 1

    now = datetime.now(timezone.utc)
    session = SessionLocal()

    try:
        required_tables = ("auth_users", "auth_roles", "auth_platform_user_roles")
        missing_tables = [table for table in required_tables if not table_exists(table)]
        if missing_tables:
            print("Database schema is not ready for platform admin bootstrap.")
            print(f"  missing_tables={', '.join(missing_tables)}")
            print(f"  database_url={DATABASE_URL}")
            print(f"  db_schema={DB_SCHEMA or '(default)'}")
            print("Run migrations first:")
            print("  alembic upgrade head")
            return 1

        # 1) Ensure auth_users row exists.
        app_user = session.execute(
            select(AppUser).where(func.lower(AppUser.email) == email),
        ).scalar_one_or_none()
        if app_user:
            app_user.status = args.status
        else:
            app_user = AppUser(email=email, status=args.status, created_at=now)
            session.add(app_user)
            session.flush()

        app_user_id = int(app_user.id)

        # 2) Ensure application_admin role exists.
        role = session.execute(
            select(Role).where(Role.code == "application_admin"),
        ).scalar_one_or_none()
        if role:
            role_id = int(role.id)
        else:
            role = Role(
                code="application_admin",
                scope="platform",
                description="Platform administrator role",
            )
            session.add(role)
            session.flush()
            role_id = int(role.id)

        # 3) Ensure platform role assignment exists.
        rel = session.execute(
            select(PlatformUserRole).where(
                PlatformUserRole.app_user_id == app_user_id,
                PlatformUserRole.role_id == role_id,
            ),
        ).scalar_one_or_none()
        if not rel:
            session.add(
                PlatformUserRole(
                    app_user_id=app_user_id,
                    role_id=role_id,
                )
            )

        session.commit()
        print("Platform admin ensured successfully.")
        print(f"  email={email}")
        print(f"  app_user_id={app_user_id}")
        print(f"  role_id={role_id} (application_admin)")
        return 0
    except SQLAlchemyError as exc:
        session.rollback()
        print(f"Database error: {exc}")
        print(f"database_url={DATABASE_URL}")
        print(f"db_schema={DB_SCHEMA or '(default)'}")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
