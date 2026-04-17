"""add tenant_red_flags and selection linkage

Revision ID: 20260414_0010
Revises: 20260412_0009
Create Date: 2026-04-14 06:05:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260414_0010"
down_revision = "20260412_0009"
branch_labels = None
depends_on = None


def _idx_names(insp: sa.Inspector, table_name: str) -> set[str]:
    try:
        return {str(i["name"]) for i in insp.get_indexes(table_name)}
    except Exception:
        return set()


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("tenant_red_flags"):
        op.create_table(
            "tenant_red_flags",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("tenant_id", sa.Integer(), nullable=False),
            sa.Column("category", sa.String(length=128), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("text", sa.Text(), nullable=False),
            sa.Column("product_tags_json", sa.Text(), nullable=True),
            sa.Column("service_tags_json", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("deleted_by_user_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["app_users.id"]),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["app_users.id"]),
            sa.ForeignKeyConstraint(["deleted_by_user_id"], ["app_users.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "category", "text", "is_deleted", name="uq_tenant_red_flags_dedupe"),
        )

    idx_names = _idx_names(insp, "tenant_red_flags")
    if "ix_tenant_red_flags_tenant_id" not in idx_names:
        op.create_index("ix_tenant_red_flags_tenant_id", "tenant_red_flags", ["tenant_id"], unique=False)
    if "ix_tenant_red_flags_created_by_user_id" not in idx_names:
        op.create_index("ix_tenant_red_flags_created_by_user_id", "tenant_red_flags", ["created_by_user_id"], unique=False)
    if "ix_tenant_red_flags_updated_by_user_id" not in idx_names:
        op.create_index("ix_tenant_red_flags_updated_by_user_id", "tenant_red_flags", ["updated_by_user_id"], unique=False)
    if "ix_tenant_red_flags_deleted_by_user_id" not in idx_names:
        op.create_index("ix_tenant_red_flags_deleted_by_user_id", "tenant_red_flags", ["deleted_by_user_id"], unique=False)

    if insp.has_table("tenant_red_flag_selections"):
        columns = {c["name"] for c in insp.get_columns("tenant_red_flag_selections")}
        uniques = {u["name"] for u in insp.get_unique_constraints("tenant_red_flag_selections") if u.get("name")}
        fks = {f.get("name") for f in insp.get_foreign_keys("tenant_red_flag_selections")}

        with op.batch_alter_table("tenant_red_flag_selections") as batch_op:
            if "tenant_red_flag_id" not in columns:
                batch_op.add_column(sa.Column("tenant_red_flag_id", sa.Integer(), nullable=True))
            # shared red flag can be nullable when selection points to tenant_red_flag_id
            if "shared_red_flag_id" in columns:
                batch_op.alter_column("shared_red_flag_id", existing_type=sa.Integer(), nullable=True)

            if "uq_tenant_red_flag_selections_scope" in uniques:
                batch_op.drop_constraint("uq_tenant_red_flag_selections_scope", type_="unique")
            if "uq_tenant_red_flag_selections_scope_shared" not in uniques:
                batch_op.create_unique_constraint(
                    "uq_tenant_red_flag_selections_scope_shared",
                    ["tenant_id", "business_unit_id", "shared_red_flag_id", "is_deleted"],
                )
            if "uq_tenant_red_flag_selections_scope_tenant" not in uniques:
                batch_op.create_unique_constraint(
                    "uq_tenant_red_flag_selections_scope_tenant",
                    ["tenant_id", "business_unit_id", "tenant_red_flag_id", "is_deleted"],
                )

            fk_name = "fk_tenant_red_flag_selections_tenant_red_flag_id"
            if fk_name not in fks:
                batch_op.create_foreign_key(
                    fk_name,
                    "tenant_red_flags",
                    ["tenant_red_flag_id"],
                    ["id"],
                )

        idx_sel = _idx_names(insp, "tenant_red_flag_selections")
        if "ix_tenant_red_flag_selections_tenant_red_flag_id" not in idx_sel:
            op.create_index(
                "ix_tenant_red_flag_selections_tenant_red_flag_id",
                "tenant_red_flag_selections",
                ["tenant_red_flag_id"],
                unique=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("tenant_red_flag_selections"):
        uniques = {u["name"] for u in insp.get_unique_constraints("tenant_red_flag_selections") if u.get("name")}
        fks = {f.get("name") for f in insp.get_foreign_keys("tenant_red_flag_selections")}
        with op.batch_alter_table("tenant_red_flag_selections") as batch_op:
            if "uq_tenant_red_flag_selections_scope_tenant" in uniques:
                batch_op.drop_constraint("uq_tenant_red_flag_selections_scope_tenant", type_="unique")
            if "uq_tenant_red_flag_selections_scope_shared" in uniques:
                batch_op.drop_constraint("uq_tenant_red_flag_selections_scope_shared", type_="unique")
            if "uq_tenant_red_flag_selections_scope" not in uniques:
                batch_op.create_unique_constraint(
                    "uq_tenant_red_flag_selections_scope",
                    ["tenant_id", "business_unit_id", "shared_red_flag_id", "is_deleted"],
                )
            fk_name = "fk_tenant_red_flag_selections_tenant_red_flag_id"
            if fk_name in fks:
                batch_op.drop_constraint(fk_name, type_="foreignkey")
            cols = {c["name"] for c in insp.get_columns("tenant_red_flag_selections")}
            if "tenant_red_flag_id" in cols:
                batch_op.drop_column("tenant_red_flag_id")

    if insp.has_table("tenant_red_flags"):
        idx_names = _idx_names(insp, "tenant_red_flags")
        if "ix_tenant_red_flags_deleted_by_user_id" in idx_names:
            op.drop_index("ix_tenant_red_flags_deleted_by_user_id", table_name="tenant_red_flags")
        if "ix_tenant_red_flags_updated_by_user_id" in idx_names:
            op.drop_index("ix_tenant_red_flags_updated_by_user_id", table_name="tenant_red_flags")
        if "ix_tenant_red_flags_created_by_user_id" in idx_names:
            op.drop_index("ix_tenant_red_flags_created_by_user_id", table_name="tenant_red_flags")
        if "ix_tenant_red_flags_tenant_id" in idx_names:
            op.drop_index("ix_tenant_red_flags_tenant_id", table_name="tenant_red_flags")
        op.drop_table("tenant_red_flags")
