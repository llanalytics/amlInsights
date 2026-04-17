"""add password hash to app users

Revision ID: 20260410_0003
Revises: 20260410_0002
Create Date: 2026-04-10 10:25:00
"""

from alembic import op
import sqlalchemy as sa

from database import DB_SCHEMA


revision = "20260410_0003"
down_revision = "20260410_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("app_users", schema=DB_SCHEMA)}
    if "password_hash" not in columns:
        op.add_column("app_users", sa.Column("password_hash", sa.String(length=255), nullable=True), schema=DB_SCHEMA)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("app_users", schema=DB_SCHEMA)}
    if "password_hash" in columns:
        op.drop_column("app_users", "password_hash", schema=DB_SCHEMA)

