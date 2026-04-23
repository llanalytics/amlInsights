from pydantic import BaseModel


class WorkflowStateOut(BaseModel):
    state_code: str
    display_name: str
    is_initial: bool
    is_terminal: bool
    capabilities: list[str] = []


class WorkflowTransitionOut(BaseModel):
    transition_code: str
    from_state_code: str
    to_state_code: str
    requires_comment: bool
    allowed_roles: list[str]


class WorkflowVersionOut(BaseModel):
    workflow_definition_id: int
    workflow_name: str
    module_code: str
    entity_type: str
    is_system_template: bool
    workflow_version_id: int
    version_no: int
    status: str
    is_active: bool
    published_at: str | None
    states: list[WorkflowStateOut]
    transitions: list[WorkflowTransitionOut]


class WorkflowCloneFrom(BaseModel):
    source: str | None = None
    workflow_definition_id: int | None = None
    workflow_version_id: int | None = None


class WorkflowDraftCreateRequest(BaseModel):
    name: str | None = None
    clone_from: WorkflowCloneFrom | None = None


class WorkflowDraftCreateResponse(BaseModel):
    success: bool
    workflow_definition_id: int
    workflow_version_id: int
    status: str


class WorkflowValidateRequest(BaseModel):
    version_id: int


class WorkflowValidateIssue(BaseModel):
    code: str
    message: str


class WorkflowValidateResponse(BaseModel):
    valid: bool
    errors: list[WorkflowValidateIssue]
    warnings: list[str]


class WorkflowPublishRequest(BaseModel):
    version_id: int
    publish_comment: str | None = None


class WorkflowPublishResponse(BaseModel):
    success: bool
    workflow_definition_id: int
    workflow_version_id: int
    status: str
    binding: dict


class WorkflowRollbackRequest(BaseModel):
    target_workflow_version_id: int
    reason: str | None = None


class WorkflowRollbackResponse(BaseModel):
    success: bool
    active_workflow_version_id: int
    rolled_back_from_workflow_version_id: int | None


class WorkflowDraftStateInput(BaseModel):
    state_code: str
    display_name: str
    is_initial: bool = False
    is_terminal: bool = False
    capabilities: list[str] = []


class WorkflowDraftTransitionInput(BaseModel):
    transition_code: str
    from_state_code: str
    to_state_code: str
    requires_comment: bool = False
    allowed_roles: list[str] = []


class WorkflowDraftUpdateRequest(BaseModel):
    version_id: int
    states: list[WorkflowDraftStateInput]
    transitions: list[WorkflowDraftTransitionInput]


class WorkflowDraftUpdateResponse(BaseModel):
    success: bool
    workflow_version_id: int
    status: str
    updated_at: str


class RedFlagSelectionCreateRequest(BaseModel):
    business_unit_id: int
    shared_red_flag_id: int | None = None
    tenant_red_flag_id: int | None = None
    relevance_status: str = "needs_review"
    rationale: str | None = None


class RedFlagSelectionUpdateRequest(BaseModel):
    relevance_status: str | None = None
    rationale: str | None = None


class RedFlagSelectionActionRequest(BaseModel):
    comment: str | None = None


class TenantRedFlagSelectionCreateRequest(BaseModel):
    business_unit_id: int
    category: str
    severity: str
    text: str
    product_tags: list[str] = []
    service_tags: list[str] = []
    relevance_status: str = "needs_review"
    rationale: str | None = None


class RedFlagSelectionOut(BaseModel):
    id: int
    tenant_id: int
    business_unit_id: int
    business_unit_code: str | None = None
    business_unit_name: str | None = None
    shared_red_flag_id: int | None = None
    tenant_red_flag_id: int | None = None
    category: str | None = None
    severity: str | None = None
    red_flag_text: str | None = None
    product_tags: list[str] = []
    service_tags: list[str] = []
    relevance_status: str
    approval_status: str
    rationale: str | None
    analyst_user_id: int | None
    approver_user_id: int | None
    submitted_at: str | None
    approved_at: str | None
    created_at: str
    updated_at: str


class RedFlagSelectionListResponse(BaseModel):
    success: bool
    total: int
    data: list[RedFlagSelectionOut]


class TenantCreateRequest(BaseModel):
    name: str
    status: str = "active"


class TenantEntitlementUpsertRequest(BaseModel):
    module_code: str
    status: str = "active"


class TenantEntitlementOut(BaseModel):
    module_code: str
    status: str
    enabled_from: str | None = None
    enabled_to: str | None = None


class TenantOut(BaseModel):
    id: int
    name: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None
    entitlements: list[TenantEntitlementOut] = []


class TenantStatusUpdateRequest(BaseModel):
    status: str


class TenantDeleteResponse(BaseModel):
    success: bool
    tenant_id: int
    deleted: bool
    forced: bool = False
    details: dict = {}


class TenantUserUpsertRequest(BaseModel):
    email: str
    role_codes: list[str] = []
    status: str = "active"


class TenantUserOut(BaseModel):
    email: str
    status: str
    role_codes: list[str]
    invite_url: str | None = None
    invite_expires_at: str | None = None


class TenantSummaryOut(BaseModel):
    id: int
    name: str
    status: str


class TenantDataHubConnectionUpsertRequest(BaseModel):
    base_url: str
    auth_type: str = "none"
    auth_header_name: str | None = None
    auth_secret_ref: str | None = None
    connect_timeout_seconds: int = 10
    read_timeout_seconds: int = 20
    is_active: bool = True


class TenantDataHubConnectionOut(BaseModel):
    tenant_id: int
    base_url: str
    auth_type: str
    auth_header_name: str | None = None
    auth_secret_ref: str | None = None
    connect_timeout_seconds: int
    read_timeout_seconds: int
    is_active: bool
    last_tested_at: str | None = None
    last_test_status: str | None = None
    last_test_message: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class BusinessUnitCreateRequest(BaseModel):
    code: str
    name: str
    status: str = "active"


class BusinessUnitUpdateRequest(BaseModel):
    code: str | None = None
    name: str | None = None
    status: str | None = None


class BusinessUnitOut(BaseModel):
    id: int
    tenant_id: int
    code: str
    name: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None
