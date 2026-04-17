"""add audit_events table

Revision ID: 20260412_0009
Revises: 20260411_0008
Create Date: 2026-04-12 12:15:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260412_0009"
down_revision = "20260411_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("audit_events"):
        op.create_table(
            "audit_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("tenant_id", sa.Integer(), nullable=True),
            sa.Column("module_code", sa.String(length=64), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("entity_type", sa.String(length=128), nullable=True),
            sa.Column("entity_id", sa.Integer(), nullable=True),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_email", sa.String(length=255), nullable=True),
            sa.Column("request_method", sa.String(length=16), nullable=True),
            sa.Column("request_path", sa.String(length=512), nullable=True),
            sa.Column("request_ip", sa.String(length=128), nullable=True),
            sa.Column("user_agent", sa.String(length=512), nullable=True),
            sa.Column("event_payload_json", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"], unique=False)
        op.create_index("ix_audit_events_module_code", "audit_events", ["module_code"], unique=False)
        op.create_index("ix_audit_events_action", "audit_events", ["action"], unique=False)
        op.create_index("ix_audit_events_entity_type", "audit_events", ["entity_type"], unique=False)
        op.create_index("ix_audit_events_entity_id", "audit_events", ["entity_id"], unique=False)
        op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"], unique=False)
        op.create_index("ix_audit_events_actor_email", "audit_events", ["actor_email"], unique=False)
        op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if insp.has_table("audit_events"):
        op.drop_index("ix_audit_events_created_at", table_name="audit_events")
        op.drop_index("ix_audit_events_actor_email", table_name="audit_events")
        op.drop_index("ix_audit_events_actor_user_id", table_name="audit_events")
        op.drop_index("ix_audit_events_entity_id", table_name="audit_events")
        op.drop_index("ix_audit_events_entity_type", table_name="audit_events")
        op.drop_index("ix_audit_events_action", table_name="audit_events")
        op.drop_index("ix_audit_events_module_code", table_name="audit_events")
        op.drop_index("ix_audit_events_tenant_id", table_name="audit_events")
        op.drop_table("audit_events")
