# AML Insights SaaS Blueprint (Draft v1)

## 1) Vision
Build `amlInsights` as a multi-tenant SaaS platform where each tenant licenses one or more compliance modules, while sharing access to a common read-only data layer (for example, regulatory red flags).

## 2) Core Product Model
- Platform: `amlInsights` (shared UI, auth, tenant management, billing, entitlements).
- Modules (licensed per tenant):
  - Red Flags Curation
  - AML Transaction Monitoring (next priority after Red Flags)
  - KYC
  - Sanctions
  - Training
- Operational Reporting:
  - Not directly licensed.
  - Available automatically when a tenant licenses at least one other module.
- Shared read-only data products:
  - Regulatory red flags (initial example)
  - Future: typologies, regulatory notices, benchmark control libraries

## 3) Tenant Experience
- Each tenant signs in to a tenant-scoped workspace.
- Tenant can license one or more modules.
- In Red Flags module, tenant reviews standard red flags and maps relevance by business unit.
- In Transaction Monitoring module, tenant designs controls, manages control lifecycle states, and maps controls to selected red flags.
- Other modules use shared tenant context and can reference cross-module entities (for example, controls mapped to KYC or sanctions risk indicators).
- Tenant management UI supports tenant administrators for user/role management.
- Platform administration UI supports application admins not tied to a tenant.

## 4) Multi-Tenant Data Strategy
- Keep a shared database with strict tenant isolation at row level.
- All tenant-owned tables include `tenant_id` (required, indexed).
- Tenant-owned red-flag and control tables also include `business_unit_id` (required, indexed where appropriate).
- Shared reference tables omit `tenant_id` and are read-only to tenant users.
- Suggested domains:
  - `tenant` domain: tenants, users, roles, invitations
  - `entitlement` domain: subscriptions, licensed modules, status
  - `shared_content` domain: red flags master catalog (read-only to tenants)
  - `tenant_content` domain: tenant-selected red flags, controls, mappings, notes, evidence
  - `operations` domain: audit logs, background jobs, module events

## 5) Licensing and Entitlements
- Entitlement model: `tenant_id + module_code + status`.
- Binary module licensing only: a tenant either has access to a module or does not.
- Gate all module APIs and UI routes with entitlement checks.
- Track API usage for telemetry, monitoring, and future commercial options.

## 6) Security and Compliance Baseline
- Authentication: centralized platform auth.
- Authorization: tenant-scoped RBAC + module permission sets, plus platform-level admin roles.
- Data isolation:
  - Enforce `tenant_id` filter server-side on every tenant-owned query.
  - Add DB-level guardrails where feasible (policies/views).
- Auditing:
  - Immutable audit trail for create/update/approve/logical-delete and key workflow decisions.
- Data deletion policy:
  - Normal management interfaces use logical delete (`is_deleted`, `deleted_at`, `deleted_by`).
  - Hard delete reserved for controlled platform admin tenant-removal workflows.
- Compliance forward look:
  - Add GDPR/data-privacy policy design before onboarding tenant customer data.
- Secrets:
  - No secrets in code or committed env files.
  - Use environment config/secrets manager per environment.

## 7) Module Interaction Pattern
- `amlInsights` frontend calls platform API gateway/services.
- Module services expose bounded APIs (not direct frontend-to-database access).
- Shared content service provides read-only canonical data (for example, red flags catalog).
- Tenant actions are stored in tenant-owned tables linked to shared content by IDs.

## 8) Suggested Initial Data Objects
- Shared:
  - `shared_red_flag` (id, source, category, severity, text, metadata, version)
- Tenant-owned:
  - `tenant_red_flag_selection` (tenant_id, business_unit_id, shared_red_flag_id, relevance_status, rationale, approval_status)
  - `tm_control` (tenant_id, business_unit_id, control_name, logic_summary, lifecycle_status)
  - `tm_control_red_flag_map` (tenant_id, business_unit_id, tm_control_id, shared_red_flag_id, mapping_strength, approval_status)
- Platform:
  - `tenant_module_entitlement` (tenant_id, module_code, enabled_from, enabled_to, status)
  - `api_usage_event` (tenant_id, module_code, endpoint, method, request_count, time_bucket)

## 9) Roles and Workflow
- Platform-level (not tenant-bound):
  - `application_admin`: manages tenants, can fully remove tenant environments.
- Tenant-level core:
  - `tenant_admin`: user/role management and tenant configuration.
  - `read_only_audit`: read-only across tenant module data for audit.
- Red Flags module:
  - `red_flag_analyst`: maps shared red flags to each business unit.
  - `red_flag_approver`: reviews and approves/rejects analyst mappings.
- AML Transaction Monitoring module:
  - `control_developer`: creates/edits controls.
  - `control_reviewer`: performs review and returns/endorses controls.
  - `control_approver`: final approval authority for control lifecycle transitions.
- Workflow requirements:
  - Audited, stateful baseline workflow for red flag relevance mapping and approval.
  - Audited, stateful baseline workflow for control development/review/approval.
  - Tenant-configurable workflow versions with platform guardrails and rollback.

## 10) Phased Build Plan
1. Platform foundation
   - Tenant/user model, platform admin + tenant admin UI, RBAC, entitlement checks, audit logging.
2. Shared red flags product
   - Keep current ingestion pipeline, publish standardized read-only red flag catalog.
3. Red Flags Curation module
   - Business-unit mapping UI with analyst/approver workflow and full audit trail.
4. Transaction Monitoring module
   - Priority module after Red Flags.
   - Control builder + lifecycle workflow + mapping to selected/shared red flags.
5. Additional modules
   - KYC, sanctions, training.
   - Operational reporting enabled whenever any licensed module exists.
6. Commercial readiness
   - Billing integration, module entitlement operations, customer admin workflows, usage analytics.

## 11) Key Architecture Decisions to Finalize Before Build
- Tenant isolation approach:
  - Single DB + row-level tenant_id enforcement (recommended initial path)
  - vs separate schemas/databases per tenant (future enterprise option)
- Identity strategy:
  - Native auth first vs external IdP/SSO from day one
- Entitlement storage and evaluation:
  - Inline checks in backend services vs centralized policy service
- Module deployment pattern:
  - Modular monolith first vs service-per-module

## 12) Open Questions for Iteration
- Business unit model at v1: flat (no hierarchy). Hierarchy can be added in a future phase.
- Should tenant-configured controls be versioned from v1 with compare/rollback?
- Which audit/report exports are mandatory for first customers?
- What are initial SLA, retention, archival, and tenant-removal policies?
- Which GDPR-like obligations must be satisfied before customer-data ingestion features launch?

## 13) Operational Reporting Baseline
- Required baseline report:
  - Users and assigned roles (platform admin where applicable, tenant roles by tenant).
- Additional recommended reports:
  - Red flag mapping decisions and approval history by business unit.
  - Control lifecycle transitions and approval history.
  - API usage by tenant/module.

## 14) Immediate Next Step (Recommended)
Create a follow-on technical spec from this blueprint:
- API contracts for shared red flags, business-unit mappings, and approval workflow
- first-pass DB schema with tenant-owned vs shared tables
- entitlement middleware contract
- MVP UI flows in `amlInsights` for:
  - platform admin tenant management
  - tenant admin user/role management
  - red flag analyst/approver workflow
  - control developer/reviewer/approver workflow
