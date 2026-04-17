# AML Insights Technical Spec v1
## Scope: Red Flags + AML Transaction Monitoring

## 1) Scope and Goals
- Implement v1 for:
  - Red Flags module (tenant relevance mapping by business unit with approval workflow).
  - AML Transaction Monitoring module (control build/review/approval and control-to-red-flag mapping).
- Use flat business unit model in v1.
- Enforce tenant isolation and full workflow auditing.
- Keep logical delete for normal management operations.

Out of scope for this spec:
- KYC, sanctions, training module implementation.
- Customer-data ingestion model (GDPR design to follow separately).

## 2) Assumptions
- Shared Postgres database.
- Application-level tenant enforcement is mandatory on every tenant-owned query.
- Operational Reporting module is available when at least one module is licensed.
- Licensing is binary per module (licensed or not licensed).
- Baseline workflows are provided by the platform; tenant-specific customization is enabled via versioned workflow configuration.

## 3) Roles and Permissions
Platform role:
- `application_admin`:
  - Manage tenants and module entitlements.
  - Hard-delete a tenant only via controlled admin flow.

Tenant roles:
- `tenant_admin`:
  - Manage tenant users and tenant role assignments.
- `read_only_audit`:
  - Read-only access to tenant module data and audit records.
- `red_flag_analyst`:
  - Create/edit red-flag relevance mappings by business unit.
- `red_flag_approver`:
  - Approve/reject red-flag mappings.
- `tm_control_developer`:
  - Create/edit transaction monitoring controls.
- `tm_control_reviewer`:
  - Review and return/recommend controls.
- `tm_control_approver`:
  - Final approve/reject for controls and control mapping changes.

## 4) Data Model (First-Pass)

### 4.1 Platform Tables
- `tenant`
  - `id` (pk), `name`, `status`, `created_at`, `updated_at`
- `user`
  - `id` (pk), `email` (unique), `status`, `created_at`, `updated_at`
- `tenant_user`
  - `id` (pk), `tenant_id` (fk), `user_id` (fk), `status`, `created_at`
- `role`
  - `id` (pk), `code` (unique), `scope` (`platform|tenant`), `description`
- `tenant_user_role`
  - `id` (pk), `tenant_user_id` (fk), `role_id` (fk), `created_at`
- `platform_user_role`
  - `id` (pk), `user_id` (fk), `role_id` (fk), `created_at`
- `tenant_module_entitlement`
  - `id` (pk), `tenant_id` (fk), `module_code`, `status`, `enabled_from`, `enabled_to`, `created_at`
  - unique: (`tenant_id`, `module_code`)

### 4.2 Shared Content Tables
- `shared_red_flag`
  - `id` (pk), `source_name`, `source_url`, `category`, `severity`, `title`, `text`, `version`, `active`, `created_at`, `updated_at`
  - optional unique key candidate: (`source_url`, `version`)

### 4.3 Tenant-Owned Core Tables
- `business_unit`
  - `id` (pk), `tenant_id` (fk), `name`, `code`, `status`, `created_at`, `updated_at`
  - flat model only in v1.
  - unique: (`tenant_id`, `code`)

- `tenant_red_flag_selection`
  - `id` (pk), `tenant_id` (fk), `business_unit_id` (fk), `shared_red_flag_id` (fk)
  - `relevance_status` (`in_scope|out_of_scope|needs_review`)
  - `approval_status` (`draft|pending_approval|approved|rejected|returned`)
  - `rationale`, `analyst_user_id`, `approver_user_id`, `submitted_at`, `approved_at`
  - logical delete fields: `is_deleted`, `deleted_at`, `deleted_by_user_id`
  - audit fields: `created_at`, `updated_at`, `created_by_user_id`, `updated_by_user_id`
  - unique: (`tenant_id`, `business_unit_id`, `shared_red_flag_id`, `is_deleted=false`)

- `tm_control`
  - `id` (pk), `tenant_id` (fk), `business_unit_id` (fk)
  - `control_code` (tenant unique), `name`, `description`, `logic_summary`
  - `lifecycle_status` (`development|SIT|MRM|UAT|rejected|retired`)
  - `review_notes`, `developer_user_id`, `reviewer_user_id`, `approver_user_id`
  - logical delete fields + standard audit fields
  - unique: (`tenant_id`, `control_code`, `is_deleted=false`)

- `tm_control_red_flag_map`
  - `id` (pk), `tenant_id` (fk), `business_unit_id` (fk), `tm_control_id` (fk), `shared_red_flag_id` (fk)
  - `mapping_strength` (`primary|secondary|supporting`)
  - `approval_status` (`draft|pending_approval|approved|rejected|returned`)
  - `rationale`, `submitted_at`, `approved_at`, `approver_user_id`
  - logical delete fields + standard audit fields

### 4.4 Audit and Usage Tables
- `workflow_event`
  - `id` (pk), `tenant_id` (nullable for platform events), `module_code`
  - `entity_type`, `entity_id`, `event_type`, `from_state`, `to_state`
  - `actor_user_id`, `event_payload_json`, `created_at`

- `api_usage_event`
  - `id` (pk), `tenant_id`, `module_code`, `endpoint`, `method`, `status_code`, `request_ts`
  - optional rollup job into hourly/daily aggregates.

### 4.5 Workflow Configuration Tables (Configurable Engine)
- `workflow_definition`
  - `id` (pk), `module_code`, `entity_type`, `name`, `is_system_template`, `created_at`
  - system templates are immutable baseline definitions.
- `workflow_definition_version`
  - `id` (pk), `workflow_definition_id` (fk), `version_no`, `status` (`draft|published|retired`)
  - `is_active`, `published_at`, `published_by_user_id`, `checksum`, `created_at`
- `workflow_state`
  - `id` (pk), `workflow_version_id` (fk), `state_code`, `display_name`, `is_initial`, `is_terminal`
- `workflow_transition`
  - `id` (pk), `workflow_version_id` (fk), `from_state_code`, `to_state_code`
  - `transition_code`, `requires_comment`, `created_at`
- `workflow_transition_role`
  - `id` (pk), `workflow_transition_id` (fk), `role_code`
- `tenant_workflow_binding`
  - `id` (pk), `tenant_id` (fk), `module_code`, `entity_type`, `workflow_version_id` (fk), `active_from`, `active_to`
  - selects which published workflow version a tenant uses for each module entity.

## 5) Workflow Model: Baseline + Tenant Customization

### 5.0 Engine Rules
- Workflow runtime is generic and reads transitions from `workflow_definition_version`.
- Each workflow-controlled entity stores `workflow_version_id` at creation time to preserve in-flight stability.
- New tenant workflow versions apply only to new records after activation; existing records continue on their bound version.
- All transitions write `workflow_event` with actor, timestamp, comment, and previous/new state.
- Validation guardrails before publish:
  - exactly one initial state
  - all non-terminal states have at least one outbound transition
  - no transition references unknown states
  - required approval checkpoints must exist
  - required auditability constraints cannot be disabled

### 5.1 Baseline Red Flag Selection Workflow
States:
- `draft` -> `pending_approval` -> (`approved` | `rejected` | `returned`)

Rules:
- Analyst can create/edit while `draft` or `returned`.
- Analyst submits to `pending_approval`.
- Approver can set `approved`, `rejected`, or `returned` with comment.
- Every transition writes a `workflow_event`.
- Approved entries become authoritative for TM mapping.

### 5.2 Baseline Control Lifecycle Workflow
States (v1 baseline):
- `draft` -> `in_review` -> (`approved` | `rejected`) -> `retired` (later transition)

Rules:
- Developer edits in `draft` or `rejected`.
- Reviewer moves `draft` to `in_review` and can return to `draft` with comments.
- Approver sets `approved` or `rejected`.
- Approved controls can have approved red-flag mappings.
- Every transition writes a `workflow_event`.

### 5.3 Baseline Control-to-Red-Flag Mapping Workflow
States:
- `draft` -> `pending_approval` -> (`approved` | `rejected` | `returned`)

Rules:
- Mapping references a specific `tm_control` and `shared_red_flag`.
- Mapping must match tenant + business unit boundaries.
- Approver role required for final approval.

### 5.4 Tenant Customization Policy
- Tenant can clone baseline workflow templates for:
  - red-flag selection workflow
  - control lifecycle workflow
  - control-to-red-flag mapping workflow
- Tenant can customize:
  - state names/codes (except reserved compliance states)
  - transitions
  - role assignments per transition
  - comment requirements per transition
- Tenant cannot customize away:
  - final approval checkpoint for regulated decisions
  - audit event creation on transition
  - logical-delete behavior
- Publishing a customized workflow requires:
  - validation pass
  - approver confirmation
  - effective date

## 6) API Specification (v1)
All endpoints require auth context and tenant scope where applicable.

### 6.1 Tenant and Admin
- `GET /api/admin/tenants`
- `POST /api/admin/tenants`
- `POST /api/admin/tenants/{tenant_id}/entitlements`
- `DELETE /api/admin/tenants/{tenant_id}` (application_admin only; hard-delete flow with confirmation)
- `GET /api/tenant/users`
- `POST /api/tenant/users`
- `POST /api/tenant/users/{tenant_user_id}/roles`
- `GET /api/admin/workflow-templates`
- `POST /api/admin/workflow-templates/{template_id}/clone` (creates tenant draft)

### 6.2 Shared Red Flags (Read-Only)
- `GET /api/red-flags/catalog`
  - filters: `category`, `severity`, `source_name`, `active`, `q`
- `GET /api/red-flags/catalog/{shared_red_flag_id}`

### 6.3 Business Unit
- `GET /api/business-units`
- `POST /api/business-units`
- `PATCH /api/business-units/{business_unit_id}`
- `DELETE /api/business-units/{business_unit_id}` (logical delete)

### 6.4 Red Flag Selections (Tenant-owned)
- `GET /api/red-flags/selections`
  - filters: `business_unit_id`, `approval_status`, `relevance_status`
- `POST /api/red-flags/selections`
- `PATCH /api/red-flags/selections/{selection_id}`
- `POST /api/red-flags/selections/{selection_id}/submit`
- `POST /api/red-flags/selections/{selection_id}/approve`
- `POST /api/red-flags/selections/{selection_id}/reject`
- `POST /api/red-flags/selections/{selection_id}/return`
- `DELETE /api/red-flags/selections/{selection_id}` (logical delete)

### 6.5 Transaction Monitoring Controls
- `GET /api/tm/controls`
- `POST /api/tm/controls`
- `PATCH /api/tm/controls/{control_id}`
- `POST /api/tm/controls/{control_id}/submit-review`
- `POST /api/tm/controls/{control_id}/approve`
- `POST /api/tm/controls/{control_id}/reject`
- `POST /api/tm/controls/{control_id}/retire`
- `DELETE /api/tm/controls/{control_id}` (logical delete)

### 6.6 Control-to-Red-Flag Mapping
- `GET /api/tm/control-mappings`
- `POST /api/tm/control-mappings`
- `PATCH /api/tm/control-mappings/{mapping_id}`
- `POST /api/tm/control-mappings/{mapping_id}/submit`
- `POST /api/tm/control-mappings/{mapping_id}/approve`
- `POST /api/tm/control-mappings/{mapping_id}/reject`
- `POST /api/tm/control-mappings/{mapping_id}/return`
- `DELETE /api/tm/control-mappings/{mapping_id}` (logical delete)

### 6.7 Operational Reporting
- `GET /api/reports/users-roles`
  - required baseline report: all users and assigned roles.
- `GET /api/reports/red-flag-mapping-history`
- `GET /api/reports/control-lifecycle-history`
- `GET /api/reports/api-usage`

### 6.8 Workflow Configuration
- `GET /api/workflows/{module_code}/{entity_type}`
  - returns active tenant workflow and version metadata.
- `POST /api/workflows/{module_code}/{entity_type}/draft`
  - initialize tenant draft from current active or baseline template.
- `PATCH /api/workflows/{module_code}/{entity_type}/draft`
  - update states/transitions/role bindings.
- `POST /api/workflows/{module_code}/{entity_type}/draft/validate`
  - run guardrail validation checks.
- `POST /api/workflows/{module_code}/{entity_type}/draft/publish`
  - publish and activate with effective date.
- `POST /api/workflows/{module_code}/{entity_type}/draft/rollback`
  - rollback binding to previous published version.

### 6.9 Workflow Payload Contracts (Draft)
`POST /api/workflows/{module_code}/{entity_type}/draft`
Request:
```json
{
  "name": "Red Flag Selection - Tenant Baseline Clone",
  "clone_from": {
    "source": "system_template",
    "workflow_definition_id": 101,
    "workflow_version_id": 3
  }
}
```
Response:
```json
{
  "success": true,
  "workflow_definition_id": 501,
  "workflow_version_id": 1,
  "status": "draft"
}
```

`PATCH /api/workflows/{module_code}/{entity_type}/draft`
Request:
```json
{
  "version_id": 1,
  "states": [
    { "state_code": "draft", "display_name": "Draft", "is_initial": true, "is_terminal": false },
    { "state_code": "pending_approval", "display_name": "Pending Approval", "is_initial": false, "is_terminal": false },
    { "state_code": "approved", "display_name": "Approved", "is_initial": false, "is_terminal": true },
    { "state_code": "rejected", "display_name": "Rejected", "is_initial": false, "is_terminal": true },
    { "state_code": "returned", "display_name": "Returned", "is_initial": false, "is_terminal": false }
  ],
  "transitions": [
    {
      "transition_code": "submit",
      "from_state_code": "draft",
      "to_state_code": "pending_approval",
      "requires_comment": false,
      "allowed_roles": ["red_flag_analyst"]
    },
    {
      "transition_code": "approve",
      "from_state_code": "pending_approval",
      "to_state_code": "approved",
      "requires_comment": true,
      "allowed_roles": ["red_flag_approver"]
    },
    {
      "transition_code": "reject",
      "from_state_code": "pending_approval",
      "to_state_code": "rejected",
      "requires_comment": true,
      "allowed_roles": ["red_flag_approver"]
    },
    {
      "transition_code": "return",
      "from_state_code": "pending_approval",
      "to_state_code": "returned",
      "requires_comment": true,
      "allowed_roles": ["red_flag_approver"]
    },
    {
      "transition_code": "resubmit",
      "from_state_code": "returned",
      "to_state_code": "pending_approval",
      "requires_comment": false,
      "allowed_roles": ["red_flag_analyst"]
    }
  ]
}
```
Response:
```json
{
  "success": true,
  "workflow_version_id": 1,
  "status": "draft",
  "updated_at": "2026-04-07T10:30:00Z"
}
```

`POST /api/workflows/{module_code}/{entity_type}/draft/validate`
Request:
```json
{
  "version_id": 1
}
```
Response:
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "State 'returned' has only one outbound transition."
  ]
}
```

`POST /api/workflows/{module_code}/{entity_type}/draft/publish`
Request:
```json
{
  "version_id": 1,
  "effective_at": "2026-04-08T00:00:00Z",
  "publish_comment": "Approved by red flag approver and tenant admin."
}
```
Response:
```json
{
  "success": true,
  "workflow_definition_id": 501,
  "workflow_version_id": 1,
  "status": "published",
  "binding": {
    "tenant_id": 12,
    "module_code": "red_flags",
    "entity_type": "tenant_red_flag_selection",
    "active_from": "2026-04-08T00:00:00Z"
  }
}
```

`POST /api/workflows/{module_code}/{entity_type}/draft/rollback`
Request:
```json
{
  "target_workflow_version_id": 7,
  "effective_at": "2026-04-08T00:00:00Z",
  "reason": "Rollback due to unexpected validation failure in UAT."
}
```
Response:
```json
{
  "success": true,
  "active_workflow_version_id": 7,
  "rolled_back_from_workflow_version_id": 8
}
```

Validation error response (example):
```json
{
  "valid": false,
  "errors": [
    {
      "code": "MISSING_REQUIRED_APPROVAL_STATE",
      "message": "At least one approval terminal state is required."
    },
    {
      "code": "INVALID_TRANSITION_ROLE",
      "message": "Role 'analyst_temp' is not defined for tenant scope."
    }
  ],
  "warnings": []
}
```

## 7) Authorization Matrix (v1 Summary)
- `application_admin`: full platform admin endpoints.
- `tenant_admin`: tenant user/role and business-unit management.
- `red_flag_analyst`: create/update/submit red-flag selections.
- `red_flag_approver`: approve/reject/return red-flag selections.
- `control_developer`: create/update/submit controls and draft mappings.
- `control_reviewer`: review/return controls.
- `control_approver`: approve/reject controls and mappings.
- `read_only_audit`: read-only across tenant data + reporting endpoints.

## 8) Logical Delete and Hard Delete Policy
- Logical delete on normal UI/API deletes.
- Exclude logically deleted rows from default queries.
- Report endpoints can optionally include deleted rows when explicitly requested by privileged roles.
- Hard delete allowed only in admin tenant-removal flow with explicit safeguards.

## 9) Non-Functional Requirements (v1)
- Auditability: every state transition and approval decision is recorded.
- Traceability: include actor, timestamp, comments in workflow events.
- Observability: track API usage by tenant/module/endpoint.
- Idempotency: state-transition endpoints reject invalid duplicate transitions gracefully.
- Pagination/filtering on all list endpoints.
- Workflow safety: publish-time structural validation and rollback support.

## 10) Initial Implementation Plan
1. Create DB migrations for platform + shared + tenant-owned + audit tables.
2. Implement auth context and tenant guard middleware.
3. Implement role/permission middleware.
4. Implement shared red-flag read-only APIs.
5. Implement business unit CRUD.
6. Implement red-flag selection workflow APIs.
7. Implement TM control and mapping workflow APIs.
8. Implement operational reporting endpoints (starting with users/roles report).
9. Add API usage event capture middleware + rollup job.
10. Implement workflow configuration APIs and version binding logic.
11. Add workflow template management UI for authorized tenant admins/approvers.

Bootstrap command for Step 1 baseline seed:
- `cd /home/ehale/Documents/amlredflags && ./scripts/seed_baseline.sh`

## 11) Follow-On Spec Items
- Control lifecycle states and transition constraints (expanded).
- Versioning strategy for controls and mappings (beyond workflow version binding).
- Tenant archival strategy after tenant removal.
- GDPR/compliance package for customer-data modules.
