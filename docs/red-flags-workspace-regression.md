# Red Flags Workspace Regression Checklist

Use this after workspace UI/API changes.

## 1. Automated smoke

Run:

```bash
chmod +x scripts/check_red_flags_workspace.sh
scripts/check_red_flags_workspace.sh
```

Optional (role-scoped run):

```bash
AML_USER_EMAIL="tenant1_analyst@tenant1.com" AML_TENANT_ID="1" scripts/check_red_flags_workspace.sh
```

Note:
- `AML_USER_EMAIL`/`AML_TENANT_ID` validate API role behavior.
- UI redirects (`/ui/...`) are session-based. To validate authenticated UI redirect targets, pass your browser session cookie:

```bash
AML_SESSION_COOKIE="session=<cookie-value>" SKIP_SERVER_START=1 PORT=8000 scripts/check_red_flags_workspace.sh
```

If your app is already running (for example via `scripts/start_local.sh`):

```bash
SKIP_SERVER_START=1 PORT=8000 scripts/check_red_flags_workspace.sh
```

Expected:
- `/health` is `200`
- legacy routes return `303` and redirect to workspace presets
- workspace UI/API return non-500 (`200`, `401`, or `403` depending on auth context)

## 2. Analyst view (`view=selections`)

URL:
- `/ui/red-flags/workspace?view=selections`

Expected:
- `Catalog` visible
- `In Flight` visible
- `Completed` hidden
- analyst can add from catalog
- analyst can submit/return/edit/delete only when allowed by policy/state

## 3. Approver view (`view=approvals&status=pending_approval`)

URL:
- `/ui/red-flags/workspace?view=approvals&status=pending_approval`

Expected:
- `Catalog` hidden
- `In Flight` visible
- `Completed` hidden
- approver can approve/reject/return when allowed by policy/state

## 4. Audit view (`view=audit`)

URL:
- `/ui/red-flags/workspace?view=audit`

Expected:
- `Catalog` hidden
- `In Flight` hidden
- `Completed` visible
- rows are read-only, audit trail modal opens from ID link

## 5. Legacy URL compatibility

Verify old bookmarks still work:
- `/ui/red-flags/selections`
- `/ui/red-flags/approvals`
- `/ui/red-flags/audit`

Expected:
- each issues `303` to corresponding workspace preset URL.
