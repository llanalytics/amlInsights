# Table Prefix Rename Plan

This plan renames tables to module/function-prefixed names while keeping the application stable throughout the transition.

## Goals
- Make table ownership obvious by module/function.
- Avoid long outages and risky big-bang schema changes.
- Preserve data and support controlled rollback.

## Prefix Standard
- `auth_`: authentication/authorization and role assignment.
- `ten_`: tenant administration and tenant-owned metadata.
- `wf_`: workflow engine tables.
- `srf_`: shared red-flag catalog.
- `trf_`: tenant red-flag workflow records.
- `ops_`: operational/audit/runtime telemetry.
- `sys_`: migration/system metadata.

## Target Rename Map
- `app_users` -> `auth_users`
- `roles` -> `auth_roles`
- `platform_user_roles` -> `auth_platform_user_roles`
- `tenant_user_roles` -> `auth_tenant_user_roles`
- `users` -> `auth_users_legacy` (or deprecate and drop later)
- `tenants` -> `ten_tenants`
- `tenant_users` -> `ten_users`
- `business_units` -> `ten_business_units`
- `tenant_module_entitlements` -> `ten_module_entitlements`
- `workflow_definitions` -> `wf_definitions`
- `workflow_definition_versions` -> `wf_definition_versions`
- `workflow_states` -> `wf_states`
- `workflow_transitions` -> `wf_transitions`
- `workflow_transition_roles` -> `wf_transition_roles`
- `tenant_workflow_bindings` -> `wf_tenant_bindings`
- `workflow_events` -> `wf_events`
- `red_flags` -> `srf_red_flags`
- `source_documents` -> `srf_source_documents`
- `red_flag_synonyms` -> `srf_synonyms`
- `batch_runs` -> `srf_batch_runs`
- `tenant_red_flags` -> `trf_red_flags`
- `tenant_red_flag_selections` -> `trf_selections`
- `audit_events` -> `ops_audit_events`
- `api_usage_events` -> `ops_api_usage_events`
- `report_runs` -> `ops_report_runs`

Migration metadata tables:
- Keep `alembic_version` as-is unless we explicitly re-platform migration tooling.
- Keep/remove extra version tables (`alembic_version_amlredflags_v2`, `alembic_version_operational_reporting`) in a dedicated cleanup phase only after backup and validation.

## Strategy
Use a two-step compatibility migration per phase:
1. Rename physical tables.
2. Create backward-compatible views with old names pointing to new tables.

This lets old code continue working while we update ORM `__tablename__` values and queries gradually.

After all code is migrated:
3. Remove compatibility views.

## Phase Plan

### Phase 0: Prep and Safety
1. Freeze deploys during rename window.
2. Full DB backup/snapshot.
3. Capture pre-migration inventory:
   - tables
   - row counts
   - constraints/indexes
4. Run smoke tests:
   - login/logout
   - tenant admin
   - red-flag workspace
   - reporting

Exit criteria:
- Backup verified.
- Baseline counts and smoke results stored.

### Phase 1: Low-Risk Operational Tables
Rename:
- `audit_events`, `api_usage_events`, `report_runs`

Actions:
1. Alembic migration: rename tables.
2. Create compatibility views using old names.
3. Run operational reporting smoke tests.

Exit criteria:
- Reporting and audit endpoints unchanged.

### Phase 2: Shared Red Flags Catalog
Rename:
- `red_flags`, `source_documents`, `red_flag_synonyms`, `batch_runs`

Actions:
1. Alembic migration: rename + recreate indexes if required.
2. Compatibility views for old names.
3. Validate crawler/batch + curation + synonym UI.

Exit criteria:
- Red-flag ingestion and curation still functional.

### Phase 3: Tenant Red Flags
Rename:
- `tenant_red_flags`, `tenant_red_flag_selections`

Actions:
1. Alembic migration: rename and validate FK relationships.
2. Compatibility views.
3. Validate workspace actions (add/edit/submit/approve/reject/return/audit trail).

Exit criteria:
- Workflow and selections stable for analyst/approver/audit roles.

### Phase 4: Workflow Engine Tables
Rename:
- `workflow_definitions`, `workflow_definition_versions`, `workflow_states`, `workflow_transitions`, `workflow_transition_roles`, `tenant_workflow_bindings`, `workflow_events`

Actions:
1. Alembic migration for workflow table rename set.
2. Compatibility views.
3. Validate workflow policy/data endpoints and tenant workflow admin.

Exit criteria:
- Workflow configuration and runtime actions pass smoke tests.

### Phase 5: Auth + Tenant Admin Core
Rename:
- `app_users`, `roles`, `platform_user_roles`, `tenant_users`, `tenant_user_roles`, `tenants`, `business_units`, `tenant_module_entitlements`

Actions:
1. Alembic migration with careful FK/index rename handling.
2. Compatibility views.
3. Validate login, tenant admin, user role assignment, entitlement updates.

Exit criteria:
- All auth/tenant admin operations stable.

### Phase 6: Code Cutover
1. Update ORM `__tablename__` to new names across models.
2. Update raw SQL statements to new table names.
3. Deploy code with compatibility views still present.
4. Run full regression.

Exit criteria:
- App runs exclusively against new table names, still backward compatible.

### Phase 7: Compatibility View Cleanup
1. Drop old-name compatibility views (one module group at a time).
2. Re-run smoke tests after each drop set.

Exit criteria:
- No old-name dependencies remain.

### Phase 8: Legacy Cleanup
1. Decide fate of `users`:
   - archive into `auth_users_legacy`, or
   - migrate remaining dependencies then drop.
2. Rationalize Alembic version table strategy.
3. Final schema documentation refresh.

Exit criteria:
- Legacy artifacts removed or documented with explicit owners.

## Migration Mechanics (Alembic)
For each phase migration:
1. `ALTER TABLE old_name RENAME TO new_name;`
2. Recreate/rename indexes and constraints where DB does not auto-adjust names.
3. Create compatibility view:
   - `CREATE VIEW old_name AS SELECT * FROM new_name;`
4. Add downgrade path:
   - drop view
   - rename table back

Notes:
- SQLite and Postgres differ in constraint/index rename behavior. Test each migration on local SQLite and Heroku Postgres before production.
- If writes must pass through old names during transition, use instead-of triggers (DB-specific) or keep code and migration tightly synchronized.

## Validation Checklist (per phase)
- Row counts match pre-phase snapshot for affected tables.
- Read endpoints succeed.
- Write endpoints succeed.
- Role-based UIs load without server errors.
- No `UndefinedTable` / `relation does not exist` errors in logs.

## Rollback Plan
1. Stop deploys.
2. Run Alembic downgrade for the active phase.
3. If downgrade fails, restore DB snapshot.
4. Re-run baseline smoke tests.

## Recommended Execution Order
1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7
9. Phase 8

## Next Step
Create migration skeletons for Phase 1 and Phase 2 first, test locally, then apply to Heroku in a maintenance window.
