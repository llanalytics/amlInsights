"""add exposure investigation sessions

Revision ID: 20260427_0019
Revises: 20260421_0018
Create Date: 2026-04-27 09:45:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260427_0019"
down_revision = "20260421_0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exp_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("ten_tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("auth_users.id"), nullable=True),
        sa.Column("created_by_email", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_exp_sessions_tenant_id", "exp_sessions", ["tenant_id"], unique=False)
    op.create_index("ix_exp_sessions_status", "exp_sessions", ["status"], unique=False)
    op.create_index("ix_exp_sessions_created_by_user_id", "exp_sessions", ["created_by_user_id"], unique=False)
    op.create_index("ix_exp_sessions_created_by_email", "exp_sessions", ["created_by_email"], unique=False)

    op.create_table(
        "exp_session_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("session_id", sa.Integer(), sa.ForeignKey("exp_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("auth_users.id"), nullable=True),
        sa.Column("created_by_email", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_exp_session_messages_session_id", "exp_session_messages", ["session_id"], unique=False)
    op.create_index("ix_exp_session_messages_tenant_id", "exp_session_messages", ["tenant_id"], unique=False)
    op.create_index(
        "ix_exp_session_messages_created_by_user_id",
        "exp_session_messages",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_exp_session_messages_created_by_email",
        "exp_session_messages",
        ["created_by_email"],
        unique=False,
    )

    op.create_table(
        "exp_session_interpretations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("session_id", sa.Integer(), sa.ForeignKey("exp_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("message_id", sa.Integer(), sa.ForeignKey("exp_session_messages.id", ondelete="SET NULL"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=True),
        sa.Column("mode", sa.String(length=64), nullable=True),
        sa.Column("intent", sa.String(length=128), nullable=True),
        sa.Column("interpretation_json", sa.Text(), nullable=True),
        sa.Column("query_plan_json", sa.Text(), nullable=True),
        sa.Column("transaction_filter_mapping_json", sa.Text(), nullable=True),
        sa.Column("response_summary", sa.Text(), nullable=True),
        sa.Column("response_payload_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_exp_session_interpretations_session_id",
        "exp_session_interpretations",
        ["session_id"],
        unique=False,
    )
    op.create_index(
        "ix_exp_session_interpretations_message_id",
        "exp_session_interpretations",
        ["message_id"],
        unique=False,
    )
    op.create_index(
        "ix_exp_session_interpretations_tenant_id",
        "exp_session_interpretations",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_exp_session_interpretations_status",
        "exp_session_interpretations",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_exp_session_interpretations_intent",
        "exp_session_interpretations",
        ["intent"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_exp_session_interpretations_intent", table_name="exp_session_interpretations")
    op.drop_index("ix_exp_session_interpretations_status", table_name="exp_session_interpretations")
    op.drop_index("ix_exp_session_interpretations_tenant_id", table_name="exp_session_interpretations")
    op.drop_index("ix_exp_session_interpretations_message_id", table_name="exp_session_interpretations")
    op.drop_index("ix_exp_session_interpretations_session_id", table_name="exp_session_interpretations")
    op.drop_table("exp_session_interpretations")

    op.drop_index("ix_exp_session_messages_created_by_email", table_name="exp_session_messages")
    op.drop_index("ix_exp_session_messages_created_by_user_id", table_name="exp_session_messages")
    op.drop_index("ix_exp_session_messages_tenant_id", table_name="exp_session_messages")
    op.drop_index("ix_exp_session_messages_session_id", table_name="exp_session_messages")
    op.drop_table("exp_session_messages")

    op.drop_index("ix_exp_sessions_created_by_email", table_name="exp_sessions")
    op.drop_index("ix_exp_sessions_created_by_user_id", table_name="exp_sessions")
    op.drop_index("ix_exp_sessions_status", table_name="exp_sessions")
    op.drop_index("ix_exp_sessions_tenant_id", table_name="exp_sessions")
    op.drop_table("exp_sessions")
