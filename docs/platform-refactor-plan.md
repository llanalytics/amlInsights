# Platform/API Ownership Refactor

## Goal
Move shared multi-tenant platform capabilities from `amlredflags` into `amlInsights`, and keep `amlredflags` focused on red-flags domain functionality.

## Target Ownership

### `amlInsights` (platform)
- Authentication context and tenant context
- Platform admin checks
- RBAC and module entitlement checks
- Workflow template and tenant workflow resolution
- Tenant/user/role operational reporting APIs

### `amlredflags` (module)
- Source crawling and article processing
- Red flag extraction and scoring
- Batch trigger/status/health for red flag ingestion
- Red flag catalog APIs (module domain APIs)

## Implemented in This Step
- Added platform middleware and dependency guards in `amlInsights`:
  - header-based context via `x-user-email`, `x-tenant-id`
- Added platform table mappings in `amlInsights` for shared DB tables.
- Added first platform API surface in `amlInsights`:
  - `GET /api/platform/auth/context`
  - `GET /api/platform/tenant/context`
  - `GET /api/platform/admin/context`
  - `GET /api/platform/admin/workflow-templates`
  - `GET /api/platform/workflows/{module_code}/{entity_type}`
  - `GET /api/platform/rbac/red-flags`
  - `GET /api/platform/rbac/transaction-monitoring`
  - `GET /api/platform/users/roles`

## Next Cutover Steps
1. Update `amlredflags` to call platform APIs (or shared library) for RBAC/workflow checks.
2. Mark duplicate platform endpoints in `amlredflags` as deprecated.
3. Remove platform models/endpoints from `amlredflags` once callers are switched.
4. Keep DB tables shared, but move migration ownership for platform tables to `amlInsights`.
