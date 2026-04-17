"""prefix auth and tenant-core tables and add compatibility views

Revision ID: 20260417_0016
Revises: 20260417_0015
Create Date: 2026-04-17 11:45:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260417_0016"
down_revision = "20260417_0015"
branch_labels = None
depends_on = None


AUTH_TENANT_RENAMES: list[tuple[str, str]] = [
    ("app_users", "auth_users"),
    ("roles", "auth_roles"),
    ("platform_user_roles", "auth_platform_user_roles"),
    ("tenant_user_roles", "auth_tenant_user_roles"),
    ("tenants", "ten_tenants"),
    ("tenant_users", "ten_users"),
    ("business_units", "ten_business_units"),
    ("tenant_module_entitlements", "ten_module_entitlements"),
]


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _table_exists(bind, table_name: str) -> bool:
    insp = sa.inspect(bind)
    return insp.has_table(table_name)


def _view_exists(bind, view_name: str) -> bool:
    insp = sa.inspect(bind)
    return view_name in set(insp.get_view_names())


def _drop_view_if_exists(bind, view_name: str) -> None:
    if _view_exists(bind, view_name):
        op.execute(f"DROP VIEW {_quote_ident(view_name)}")


def upgrade() -> None:
    bind = op.get_bind()

    for old_name, new_name in AUTH_TENANT_RENAMES:
        # If old name is already a view from a partial prior run, remove it.
        _drop_view_if_exists(bind, old_name)

        old_exists = _table_exists(bind, old_name)
        new_exists = _table_exists(bind, new_name)

        if old_exists and not new_exists:
            op.execute(
                f"ALTER TABLE {_quote_ident(old_name)} RENAME TO {_quote_ident(new_name)}"
            )

        # Backward compatibility view: old_name -> new_name
        if _table_exists(bind, new_name) and not _table_exists(bind, old_name):
            _drop_view_if_exists(bind, old_name)
            op.execute(
                f"CREATE VIEW {_quote_ident(old_name)} AS "
                f"SELECT * FROM {_quote_ident(new_name)}"
            )


def downgrade() -> None:
    bind = op.get_bind()

    for old_name, new_name in AUTH_TENANT_RENAMES:
        _drop_view_if_exists(bind, old_name)

        old_exists = _table_exists(bind, old_name)
        new_exists = _table_exists(bind, new_name)

        if new_exists and not old_exists:
            op.execute(
                f"ALTER TABLE {_quote_ident(new_name)} RENAME TO {_quote_ident(old_name)}"
            )
