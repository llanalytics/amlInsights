"""prefix shared red-flag tables and add compatibility views

Revision ID: 20260417_0013
Revises: 20260417_0012
Create Date: 2026-04-17 10:10:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260417_0013"
down_revision = "20260417_0012"
branch_labels = None
depends_on = None


SHARED_RENAMES: list[tuple[str, str]] = [
    ("red_flags", "srf_red_flags"),
    ("source_documents", "srf_source_documents"),
    ("red_flag_synonyms", "srf_synonyms"),
    ("batch_runs", "srf_batch_runs"),
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

    for old_name, new_name in SHARED_RENAMES:
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

    for old_name, new_name in SHARED_RENAMES:
        _drop_view_if_exists(bind, old_name)

        old_exists = _table_exists(bind, old_name)
        new_exists = _table_exists(bind, new_name)

        if new_exists and not old_exists:
            op.execute(
                f"ALTER TABLE {_quote_ident(new_name)} RENAME TO {_quote_ident(old_name)}"
            )
