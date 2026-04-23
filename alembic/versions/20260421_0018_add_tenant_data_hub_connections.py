"""add tenant data hub connections table

Revision ID: 20260421_0018
Revises: 20260417_0017
Create Date: 2026-04-21 10:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260421_0018"
down_revision = "20260417_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ten_data_hub_connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("ten_tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("auth_type", sa.String(length=32), nullable=False, server_default="none"),
        sa.Column("auth_header_name", sa.String(length=128), nullable=True),
        sa.Column("auth_secret_ref", sa.String(length=255), nullable=True),
        sa.Column("connect_timeout_seconds", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("read_timeout_seconds", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_status", sa.String(length=32), nullable=True),
        sa.Column("last_test_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", name="uq_tenant_data_hub_connections_tenant_id"),
    )
    op.create_index(
        "ix_ten_data_hub_connections_tenant_id",
        "ten_data_hub_connections",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ten_data_hub_connections_tenant_id", table_name="ten_data_hub_connections")
    op.drop_table("ten_data_hub_connections")

