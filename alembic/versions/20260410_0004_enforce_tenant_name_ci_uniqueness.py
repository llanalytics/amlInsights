"""enforce case-insensitive tenant name uniqueness

Revision ID: 20260410_0004
Revises: 20260410_0003
Create Date: 2026-04-10 11:05:00
"""

from alembic import op
import sqlalchemy as sa

from database import DB_SCHEMA


revision = "20260410_0004"
down_revision = "20260410_0003"
branch_labels = None
depends_on = None


def _has_duplicate_normalized_names(bind) -> list[str]:
    schema_prefix = f'"{DB_SCHEMA}".' if DB_SCHEMA and bind.dialect.name != "sqlite" else ""
    query = sa.text(
        "select lower(trim(name)) as normalized_name "
        f"from {schema_prefix}tenants "
        "group by lower(trim(name)) "
        "having count(*) > 1"
    )
    return [str(row[0]) for row in bind.execute(query).fetchall()]


def upgrade() -> None:
    bind = op.get_bind()
    duplicates = _has_duplicate_normalized_names(bind)
    if duplicates:
        names = ", ".join(duplicates)
        raise RuntimeError(
            "Cannot enforce tenant name uniqueness. "
            f"Duplicate normalized tenant names exist: {names}"
        )

    if bind.dialect.name == "sqlite":
        op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_name_ci ON tenants (lower(trim(name)))")
    else:
        op.execute(
            sa.text(
                f'CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_name_ci ON "{DB_SCHEMA}".tenants (lower(btrim(name)))'
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP INDEX IF EXISTS uq_tenants_name_ci")
    else:
        op.execute(sa.text(f'DROP INDEX IF EXISTS "{DB_SCHEMA}".uq_tenants_name_ci'))

