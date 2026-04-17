from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from database import SessionLocal
from platform_models import (
    AppUser,
    PlatformUserRole,
    Role,
    TenantModuleEntitlement,
    TenantUser,
    TenantUserRole,
)


@dataclass
class AuthContext:
    user_email: str | None = None
    tenant_id: int | None = None


class AuthContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        session = scope.get("session") or {}
        session_user = session.get("user_email") or session.get("user")
        raw_user_email = headers.get("x-user-email") or session_user
        normalized_user_email = str(raw_user_email).strip().lower() if raw_user_email else None
        ctx = AuthContext(
            user_email=normalized_user_email,
            tenant_id=int(headers["x-tenant-id"]) if headers.get("x-tenant-id", "").isdigit() else None,
        )
        scope.setdefault("state", {})
        scope["state"]["auth_context"] = ctx
        await self.app(scope, receive, send)


def get_db() -> Session:
    return SessionLocal()


def get_auth_context(request: Request) -> AuthContext:
    ctx = getattr(request.state, "auth_context", None)
    if ctx is None:
        return AuthContext()
    return ctx


def require_authenticated_user(
    auth: AuthContext = Depends(get_auth_context),
    x_user_email: str | None = Header(default=None, alias="x-user-email"),
):
    email = x_user_email or auth.user_email
    if not email:
        raise HTTPException(status_code=401, detail="Authenticated session or x-user-email header is required.")
    auth.user_email = str(email).strip().lower()
    return auth


def require_tenant_context(
    auth: AuthContext = Depends(require_authenticated_user),
    x_tenant_id: int | None = Header(default=None, alias="x-tenant-id"),
):
    tenant_id = x_tenant_id or auth.tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="x-tenant-id header is required.")
    auth.tenant_id = tenant_id
    return auth


def _resolve_user_id(db: Session, email: str) -> int:
    normalized = str(email).strip().lower()
    user = db.query(AppUser.id).filter(AppUser.email == normalized).first()
    if not user:
        raise HTTPException(status_code=403, detail=f"Unknown user: {normalized}")
    return int(user[0])


def require_platform_admin(
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    user_id = _resolve_user_id(db, auth.user_email or "")
    admin_role = (
        db.query(Role.id)
        .filter(Role.code == "application_admin")
        .first()
    )
    if not admin_role:
        raise HTTPException(status_code=403, detail="Platform admin role not configured.")

    has_role = (
        db.query(PlatformUserRole.id)
        .filter(
            PlatformUserRole.app_user_id == user_id,
            PlatformUserRole.role_id == int(admin_role[0]),
        )
        .first()
    )
    if not has_role:
        raise HTTPException(status_code=403, detail="Application admin role required.")
    return auth


def require_tenant_permission(module_code: str, *allowed_roles: str):
    def _dependency(
        auth: AuthContext = Depends(require_tenant_context),
        db: Session = Depends(get_db),
    ):
        user_id = _resolve_user_id(db, auth.user_email or "")

        entitlement = (
            db.query(TenantModuleEntitlement.id)
            .filter(
                TenantModuleEntitlement.tenant_id == auth.tenant_id,
                TenantModuleEntitlement.module_code == module_code,
                TenantModuleEntitlement.status == "active",
            )
            .first()
        )
        if not entitlement:
            raise HTTPException(status_code=403, detail=f"Tenant is not entitled for module '{module_code}'.")

        tenant_user = (
            db.query(TenantUser.id)
            .filter(
                TenantUser.tenant_id == auth.tenant_id,
                TenantUser.app_user_id == user_id,
            )
            .first()
        )
        if not tenant_user:
            raise HTTPException(status_code=403, detail="User is not assigned to the tenant.")

        rows = (
            db.query(Role.code)
            .join(TenantUserRole, TenantUserRole.role_id == Role.id)
            .filter(TenantUserRole.tenant_user_id == int(tenant_user[0]))
            .all()
        )
        role_codes = {r[0] for r in rows}
        if not role_codes.intersection(set(allowed_roles)):
            raise HTTPException(
                status_code=403,
                detail=f"Missing required role for module '{module_code}'. Expected one of: {', '.join(allowed_roles)}",
            )

        return auth

    return _dependency


def require_tenant_admin_or_platform_admin(
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    user_id = _resolve_user_id(db, auth.user_email or "")

    # Platform admin can administer any tenant.
    admin_role = db.query(Role.id).filter(Role.code == "application_admin").first()
    if admin_role:
        has_platform_admin = (
            db.query(PlatformUserRole.id)
            .filter(
                PlatformUserRole.app_user_id == user_id,
                PlatformUserRole.role_id == int(admin_role[0]),
            )
            .first()
        )
        if has_platform_admin:
            return auth

    # Otherwise require tenant_admin role on this tenant.
    tenant_user = (
        db.query(TenantUser.id)
        .filter(
            TenantUser.tenant_id == auth.tenant_id,
            TenantUser.app_user_id == user_id,
        )
        .first()
    )
    if not tenant_user:
        raise HTTPException(status_code=403, detail="User is not assigned to the tenant.")

    has_tenant_admin = (
        db.query(TenantUserRole.id)
        .join(Role, Role.id == TenantUserRole.role_id)
        .filter(
            TenantUserRole.tenant_user_id == int(tenant_user[0]),
            Role.code == "tenant_admin",
        )
        .first()
    )
    if not has_tenant_admin:
        raise HTTPException(status_code=403, detail="Tenant admin role required.")
    return auth
