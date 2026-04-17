"""bootstrap platform schema tables

Revision ID: 20260410_0002
Revises: 20260331_0001
Create Date: 2026-04-10 09:00:00
"""

from alembic import op

from database import Base
from models import User  # noqa: F401
from platform_models import (  # noqa: F401
    AppUser,
    BusinessUnit,
    PlatformUserRole,
    RedFlag,
    Role,
    Tenant,
    TenantModuleEntitlement,
    TenantRedFlagSelection,
    TenantUser,
    TenantUserRole,
    TenantWorkflowBinding,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowEvent,
    WorkflowState,
    WorkflowTransition,
    WorkflowTransitionRole,
)


revision = "20260410_0002"
down_revision = "20260331_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Bootstrap missing tables in existing environments without dropping data.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    # Intentionally no-op to avoid destructive table drops.
    pass

