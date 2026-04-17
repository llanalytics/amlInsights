"""seed tenant_admin role

Revision ID: 20260410_0005
Revises: 20260410_0004
Create Date: 2026-04-10 11:25:00
"""

from alembic import op
import sqlalchemy as sa

from database import DB_SCHEMA


revision = "20260410_0005"
down_revision = "20260410_0004"
branch_labels = None
depends_on = None


def _table_ref(table_name: str) -> str:
    if DB_SCHEMA:
        return f'"{DB_SCHEMA}".{table_name}'
    return table_name


def upgrade() -> None:
    roles_ref = _table_ref("roles")
    bind = op.get_bind()
    exists = bind.execute(
        sa.text(f"select id from {roles_ref} where code = :code"),
        {"code": "tenant_admin"},
    ).first()
    if not exists:
        bind.execute(
            sa.text(
                f"insert into {roles_ref} (code, scope, description) values (:code, :scope, :description)"
            ),
            {
                "code": "tenant_admin",
                "scope": "tenant",
                "description": "Tenant administrator role",
            },
        )


def downgrade() -> None:
    roles_ref = _table_ref("roles")
    bind = op.get_bind()
    bind.execute(
        sa.text(f"delete from {roles_ref} where code = :code"),
        {"code": "tenant_admin"},
    )

