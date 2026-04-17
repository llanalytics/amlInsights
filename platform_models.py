from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class AppUser(Base):
    __tablename__ = "auth_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    invite_token_hash: Mapped[str | None] = mapped_column(String(64))
    invite_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Tenant(Base):
    __tablename__ = "ten_tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Role(Base):
    __tablename__ = "auth_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    scope: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))


class TenantUser(Base):
    __tablename__ = "ten_users"
    __table_args__ = (UniqueConstraint("tenant_id", "app_user_id", name="uq_tenant_users_tenant_id_app_user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    app_user_id: Mapped[int] = mapped_column(ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TenantUserRole(Base):
    __tablename__ = "auth_tenant_user_roles"
    __table_args__ = (UniqueConstraint("tenant_user_id", "role_id", name="uq_tenant_user_roles_unique"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_user_id: Mapped[int] = mapped_column(ForeignKey("ten_users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("auth_roles.id", ondelete="CASCADE"), nullable=False, index=True)


class PlatformUserRole(Base):
    __tablename__ = "auth_platform_user_roles"
    __table_args__ = (UniqueConstraint("app_user_id", "role_id", name="uq_platform_user_roles_app_user_id_role_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_user_id: Mapped[int] = mapped_column(ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("auth_roles.id", ondelete="CASCADE"), nullable=False, index=True)


class TenantModuleEntitlement(Base):
    __tablename__ = "ten_module_entitlements"
    __table_args__ = (UniqueConstraint("tenant_id", "module_code", name="uq_tenant_module_entitlements_tenant_id_module_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    module_code: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    enabled_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enabled_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WorkflowDefinition(Base):
    __tablename__ = "wf_definitions"
    __table_args__ = (UniqueConstraint("module_code", "entity_type", "tenant_id", name="uq_workflow_definitions_scope"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module_code: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_system_template: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WorkflowDefinitionVersion(Base):
    __tablename__ = "wf_definition_versions"
    __table_args__ = (UniqueConstraint("workflow_definition_id", "version_no", name="uq_workflow_definition_versions"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_definition_id: Mapped[int] = mapped_column(
        ForeignKey("wf_definitions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WorkflowState(Base):
    __tablename__ = "wf_states"
    __table_args__ = (UniqueConstraint("workflow_version_id", "state_code", name="uq_workflow_states_unique"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_version_id: Mapped[int] = mapped_column(
        ForeignKey("wf_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    state_code: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[str] = mapped_column(String(150), nullable=False)
    is_initial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_terminal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    capabilities_json: Mapped[str | None] = mapped_column(Text)


class WorkflowTransition(Base):
    __tablename__ = "wf_transitions"
    __table_args__ = (UniqueConstraint("workflow_version_id", "transition_code", name="uq_workflow_transitions_unique"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_version_id: Mapped[int] = mapped_column(
        ForeignKey("wf_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    transition_code: Mapped[str] = mapped_column(String(100), nullable=False)
    from_state_code: Mapped[str] = mapped_column(String(100), nullable=False)
    to_state_code: Mapped[str] = mapped_column(String(100), nullable=False)
    requires_comment: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class WorkflowTransitionRole(Base):
    __tablename__ = "wf_transition_roles"
    __table_args__ = (UniqueConstraint("workflow_transition_id", "role_code", name="uq_workflow_transition_roles_unique"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_transition_id: Mapped[int] = mapped_column(
        ForeignKey("wf_transitions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role_code: Mapped[str] = mapped_column(String(100), nullable=False)


class TenantWorkflowBinding(Base):
    __tablename__ = "wf_tenant_bindings"
    __table_args__ = (UniqueConstraint("tenant_id", "module_code", "entity_type", name="uq_tenant_workflow_bindings"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    module_code: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    workflow_version_id: Mapped[int] = mapped_column(
        ForeignKey("wf_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


class BusinessUnit(Base):
    __tablename__ = "ten_business_units"
    __table_args__ = (UniqueConstraint("tenant_id", "code", name="uq_business_units_tenant_id_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RedFlag(Base):
    __tablename__ = "srf_red_flags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(Integer, index=True)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_category: Mapped[str | None] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    text: Mapped[str] = mapped_column(String, nullable=False)
    confidence_score: Mapped[int | None] = mapped_column(Integer)
    product_tags_json: Mapped[str | None] = mapped_column(Text)
    service_tags_json: Mapped[str | None] = mapped_column(Text)
    raw_product_tags_json: Mapped[str | None] = mapped_column(Text)
    raw_service_tags_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SourceDocument(Base):
    __tablename__ = "srf_source_documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)


class RedFlagSynonym(Base):
    __tablename__ = "srf_synonyms"
    __table_args__ = (
        UniqueConstraint("scope", "raw_value_key", name="uq_red_flag_synonyms_scope_raw_value_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # category | product | service
    raw_value: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_value_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    canonical_value: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TenantRedFlag(Base):
    __tablename__ = "trf_red_flags"
    __table_args__ = (
        UniqueConstraint("tenant_id", "category", "text", "is_deleted", name="uq_tenant_red_flags_dedupe"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    product_tags_json: Mapped[str | None] = mapped_column(Text)
    service_tags_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)
    updated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)


class TenantRedFlagSelection(Base):
    __tablename__ = "trf_selections"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "business_unit_id",
            "shared_red_flag_id",
            "is_deleted",
            name="uq_tenant_red_flag_selections_scope_shared",
        ),
        UniqueConstraint(
            "tenant_id",
            "business_unit_id",
            "tenant_red_flag_id",
            "is_deleted",
            name="uq_tenant_red_flag_selections_scope_tenant",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    business_unit_id: Mapped[int] = mapped_column(ForeignKey("ten_business_units.id"), nullable=False, index=True)
    shared_red_flag_id: Mapped[int | None] = mapped_column(ForeignKey("srf_red_flags.id"), index=True)
    tenant_red_flag_id: Mapped[int | None] = mapped_column(ForeignKey("trf_red_flags.id"), index=True)
    relevance_status: Mapped[str] = mapped_column(String(32), nullable=False, default="needs_review")
    approval_status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    rationale: Mapped[str | None] = mapped_column(String)
    analyst_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)
    approver_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)
    updated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("auth_users.id"), index=True)


class WorkflowEvent(Base):
    __tablename__ = "wf_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, index=True)
    module_code: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(64))
    to_state: Mapped[str | None] = mapped_column(String(64))
    actor_user_id: Mapped[int | None] = mapped_column(Integer, index=True)
    event_payload_json: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "ops_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, index=True)
    module_code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(128), index=True)
    entity_id: Mapped[int | None] = mapped_column(Integer, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(255), index=True)
    request_method: Mapped[str | None] = mapped_column(String(16))
    request_path: Mapped[str | None] = mapped_column(String(512))
    request_ip: Mapped[str | None] = mapped_column(String(128))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    event_payload_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
