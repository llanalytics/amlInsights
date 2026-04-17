"""add capabilities_json to workflow_states

Revision ID: 20260416_0011
Revises: 20260414_0010
Create Date: 2026-04-16 08:40:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260416_0011"
down_revision = "20260414_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("workflow_states"):
        return
    columns = {c["name"] for c in insp.get_columns("workflow_states")}
    if "capabilities_json" not in columns:
        with op.batch_alter_table("workflow_states") as batch_op:
            batch_op.add_column(sa.Column("capabilities_json", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table("workflow_states"):
        return
    columns = {c["name"] for c in insp.get_columns("workflow_states")}
    if "capabilities_json" in columns:
        with op.batch_alter_table("workflow_states") as batch_op:
            batch_op.drop_column("capabilities_json")
