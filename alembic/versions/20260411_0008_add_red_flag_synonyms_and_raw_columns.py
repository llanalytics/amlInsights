"""add red flag synonyms table and raw prediction columns

Revision ID: 20260411_0008
Revises: 20260410_0007
Create Date: 2026-04-11 10:20:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260411_0008"
down_revision = "20260410_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    existing_columns = {c["name"] for c in insp.get_columns("red_flags")}
    if "raw_category" not in existing_columns:
        op.add_column("red_flags", sa.Column("raw_category", sa.String(length=256), nullable=True))
    if "raw_product_tags_json" not in existing_columns:
        op.add_column("red_flags", sa.Column("raw_product_tags_json", sa.Text(), nullable=True))
    if "raw_service_tags_json" not in existing_columns:
        op.add_column("red_flags", sa.Column("raw_service_tags_json", sa.Text(), nullable=True))

    if not insp.has_table("red_flag_synonyms"):
        op.create_table(
            "red_flag_synonyms",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("scope", sa.String(length=32), nullable=False),
            sa.Column("raw_value", sa.String(length=255), nullable=False),
            sa.Column("raw_value_key", sa.String(length=255), nullable=False),
            sa.Column("canonical_value", sa.String(length=128), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("scope", "raw_value_key", name="uq_red_flag_synonyms_scope_raw_value_key"),
        )
        op.create_index("ix_red_flag_synonyms_scope", "red_flag_synonyms", ["scope"], unique=False)
        op.create_index("ix_red_flag_synonyms_raw_value_key", "red_flag_synonyms", ["raw_value_key"], unique=False)
        op.create_index("ix_red_flag_synonyms_canonical_value", "red_flag_synonyms", ["canonical_value"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("red_flag_synonyms"):
        op.drop_index("ix_red_flag_synonyms_canonical_value", table_name="red_flag_synonyms")
        op.drop_index("ix_red_flag_synonyms_raw_value_key", table_name="red_flag_synonyms")
        op.drop_index("ix_red_flag_synonyms_scope", table_name="red_flag_synonyms")
        op.drop_table("red_flag_synonyms")

    existing_columns = {c["name"] for c in insp.get_columns("red_flags")}
    if "raw_service_tags_json" in existing_columns:
        op.drop_column("red_flags", "raw_service_tags_json")
    if "raw_product_tags_json" in existing_columns:
        op.drop_column("red_flags", "raw_product_tags_json")
    if "raw_category" in existing_columns:
        op.drop_column("red_flags", "raw_category")
