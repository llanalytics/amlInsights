"""add product/service tag columns to red_flags

Revision ID: 20260410_0007
Revises: 20260410_0006
Create Date: 2026-04-10 18:20:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260410_0007"
down_revision = "20260410_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    existing_columns = {c["name"] for c in insp.get_columns("red_flags")}

    if "product_tags_json" not in existing_columns:
        op.add_column("red_flags", sa.Column("product_tags_json", sa.Text(), nullable=True))
    if "service_tags_json" not in existing_columns:
        op.add_column("red_flags", sa.Column("service_tags_json", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    existing_columns = {c["name"] for c in insp.get_columns("red_flags")}

    if "service_tags_json" in existing_columns:
        op.drop_column("red_flags", "service_tags_json")
    if "product_tags_json" in existing_columns:
        op.drop_column("red_flags", "product_tags_json")
