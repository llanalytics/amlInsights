"""add invite token fields to app users

Revision ID: 20260410_0006
Revises: 20260410_0005
Create Date: 2026-04-10 12:00:00
"""

from alembic import op
import sqlalchemy as sa

from database import DB_SCHEMA


revision = "20260410_0006"
down_revision = "20260410_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("app_users", schema=DB_SCHEMA)}

    if "invite_token_hash" not in columns:
        op.add_column("app_users", sa.Column("invite_token_hash", sa.String(length=64), nullable=True), schema=DB_SCHEMA)
    if "invite_token_expires_at" not in columns:
        op.add_column(
            "app_users",
            sa.Column("invite_token_expires_at", sa.DateTime(timezone=True), nullable=True),
            schema=DB_SCHEMA,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("app_users", schema=DB_SCHEMA)}

    if "invite_token_expires_at" in columns:
        op.drop_column("app_users", "invite_token_expires_at", schema=DB_SCHEMA)
    if "invite_token_hash" in columns:
        op.drop_column("app_users", "invite_token_hash", schema=DB_SCHEMA)

