"""drop old-name compatibility views after prefix cutover

Revision ID: 20260417_0017
Revises: 20260417_0016
Create Date: 2026-04-17 12:20:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260417_0017"
down_revision = "20260417_0016"
branch_labels = None
depends_on = None


COMPAT_VIEWS: list[tuple[str, str]] = [
    # Phase 1: ops
    ("audit_events", "ops_audit_events"),
    ("api_usage_events", "ops_api_usage_events"),
    ("report_runs", "ops_report_runs"),
    # Phase 2: shared red flags
    ("red_flags", "srf_red_flags"),
    ("source_documents", "srf_source_documents"),
    ("red_flag_synonyms", "srf_synonyms"),
    ("batch_runs", "srf_batch_runs"),
    # Phase 3: tenant red flags
    ("tenant_red_flags", "trf_red_flags"),
    ("tenant_red_flag_selections", "trf_selections"),
    # Phase 4: workflow
    ("workflow_definitions", "wf_definitions"),
    ("workflow_definition_versions", "wf_definition_versions"),
    ("workflow_states", "wf_states"),
    ("workflow_transitions", "wf_transitions"),
    ("workflow_transition_roles", "wf_transition_roles"),
    ("tenant_workflow_bindings", "wf_tenant_bindings"),
    ("workflow_events", "wf_events"),
    # Phase 5: auth + tenant core
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


def _view_exists(bind, name: str) -> bool:
    insp = sa.inspect(bind)
    return name in set(insp.get_view_names())


def _table_exists(bind, name: str) -> bool:
    insp = sa.inspect(bind)
    return insp.has_table(name)


def upgrade() -> None:
    bind = op.get_bind()
    for old_name, _new_name in COMPAT_VIEWS:
        if _view_exists(bind, old_name):
            op.execute(f"DROP VIEW {_quote_ident(old_name)}")


def downgrade() -> None:
    bind = op.get_bind()
    for old_name, new_name in COMPAT_VIEWS:
        if _view_exists(bind, old_name):
            continue
        if _table_exists(bind, old_name):
            continue
        if _table_exists(bind, new_name):
            op.execute(
                f"CREATE VIEW {_quote_ident(old_name)} AS "
                f"SELECT * FROM {_quote_ident(new_name)}"
            )
