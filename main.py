import os
import secrets
import json
import hashlib
import re
import csv
import io
from copy import deepcopy
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import Integer, and_, func, inspect, literal
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

from auth import hash_password, needs_rehash, verify_password
from database import DB_SCHEMA, SessionLocal, engine
from models import User
from platform_auth import (
    AuthContext,
    AuthContextMiddleware,
    require_authenticated_user,
    require_platform_admin,
    require_tenant_admin_or_platform_admin,
    require_tenant_context,
    require_tenant_permission,
)
from platform_models import (
    AppUser,
    PlatformUserRole,
    Tenant,
    Role,
    TenantModuleEntitlement,
    TenantDataHubConnection,
    BusinessUnit,
    RedFlag,
    SourceDocument,
    TenantRedFlag,
    RedFlagSynonym,
    TenantUser,
    TenantRedFlagSelection,
    TenantUserRole,
    TenantWorkflowBinding,
    WorkflowEvent,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowState,
    WorkflowTransition,
    WorkflowTransitionRole,
    AuditEvent,
)
from platform_schemas import WorkflowVersionOut
from platform_schemas import (
    WorkflowDraftCreateRequest,
    WorkflowDraftCreateResponse,
    WorkflowDraftUpdateRequest,
    WorkflowDraftUpdateResponse,
    WorkflowPublishRequest,
    WorkflowPublishResponse,
    TenantCreateRequest,
    TenantStatusUpdateRequest,
    TenantDeleteResponse,
    TenantEntitlementUpsertRequest,
    TenantOut,
    TenantEntitlementOut,
    TenantSummaryOut,
    TenantDataHubConnectionOut,
    TenantDataHubConnectionUpsertRequest,
    TenantUserOut,
    TenantUserUpsertRequest,
    BusinessUnitCreateRequest,
    BusinessUnitUpdateRequest,
    BusinessUnitOut,
    RedFlagSelectionActionRequest,
    RedFlagSelectionCreateRequest,
    RedFlagSelectionListResponse,
    RedFlagSelectionOut,
    RedFlagSelectionUpdateRequest,
    TenantRedFlagSelectionCreateRequest,
    WorkflowRollbackRequest,
    WorkflowRollbackResponse,
    WorkflowStateOut,
    WorkflowTransitionOut,
    WorkflowValidateIssue,
    WorkflowValidateRequest,
    WorkflowValidateResponse,
)

SUPPORTED_MODULE_CODES = (
    "red_flags",
    "transaction_monitoring",
    "operational_reporting",
    "kyc",
    "sanctions",
    "training",
)

OPERATIONAL_REPORT_DEFINITIONS: dict[str, dict[str, str | tuple[str, ...]]] = {
    "users_by_role": {
        "name": "Users By Role",
        "description": "Lists users and their roles for a tenant.",
        "roles": ("tenant_admin", "read_only_audit"),
    },
    "module_entitlements": {
        "name": "Entitlements Report",
        "description": "Lists module entitlements and statuses for a tenant.",
        "roles": ("tenant_admin", "read_only_audit"),
    },
    "red_flag_workspace_capabilities": {
        "name": "Red Flag Workspace Capabilities By Role",
        "description": "Shows red-flag workspace capabilities available to each role.",
        "roles": ("tenant_admin", "read_only_audit"),
    },
}

DEFAULT_TENANT_ROLE_CODES: tuple[str, ...] = (
    "tenant_admin",
    "tenant_investigator",
    "red_flag_analyst",
    "red_flag_approver",
    "read_only_audit",
    "control_developer",
    "control_reviewer",
    "control_approver",
)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "").strip()
OPENAI_CATALOG_ASSISTANT_ENABLED = os.environ.get("OPENAI_CATALOG_ASSISTANT_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
OPENAI_CATALOG_ASSISTANT_TIMEOUT_SECONDS = int(
    os.environ.get("OPENAI_CATALOG_ASSISTANT_TIMEOUT_SECONDS", "20").strip() or "20"
)
OPENAI_EXPOSURE_ASSISTANT_ENABLED = os.environ.get("OPENAI_EXPOSURE_ASSISTANT_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
OPENAI_EXPOSURE_ASSISTANT_TIMEOUT_SECONDS = int(
    os.environ.get("OPENAI_EXPOSURE_ASSISTANT_TIMEOUT_SECONDS", "20").strip() or "20"
)
OPENAI_EXPOSURE_INTENT_ROUTER_ENABLED = os.environ.get("OPENAI_EXPOSURE_INTENT_ROUTER_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
OPENAI_EXPOSURE_INTENT_ROUTER_TIMEOUT_SECONDS = int(
    os.environ.get("OPENAI_EXPOSURE_INTENT_ROUTER_TIMEOUT_SECONDS", "15").strip() or "15"
)
EXPOSURE_INTENT_ROUTE_CONFIDENCE_THRESHOLD = float(
    os.environ.get("EXPOSURE_INTENT_ROUTE_CONFIDENCE_THRESHOLD", "0.55").strip() or "0.55"
)
OPENAI_EXPOSURE_FILTER_MAPPER_ENABLED = os.environ.get("OPENAI_EXPOSURE_FILTER_MAPPER_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
OPENAI_EXPOSURE_FILTER_MAPPER_TIMEOUT_SECONDS = int(
    os.environ.get("OPENAI_EXPOSURE_FILTER_MAPPER_TIMEOUT_SECONDS", "12").strip() or "12"
)
EXPOSURE_FILTER_MAPPER_CONFIDENCE_THRESHOLD = float(
    os.environ.get("EXPOSURE_FILTER_MAPPER_CONFIDENCE_THRESHOLD", "0.6").strip() or "0.6"
)
EXPOSURE_INTENTS_CONFIG_PATH = os.environ.get("EXPOSURE_INTENTS_CONFIG_PATH", "config/exposure_intents.json").strip()


class AdminRedFlagCreateRequest(BaseModel):
    document_id: int = Field(default=0, ge=0)
    category: str = Field(min_length=1, max_length=128)
    severity: str = Field(min_length=1, max_length=20)
    text: str = Field(min_length=1)
    confidence_score: int | None = Field(default=None, ge=0, le=100)
    product_tags: list[str] = Field(default_factory=list)
    service_tags: list[str] = Field(default_factory=list)


class AdminRedFlagUpdateRequest(BaseModel):
    category: str | None = Field(default=None, min_length=1, max_length=128)
    severity: str | None = Field(default=None, min_length=1, max_length=20)
    text: str | None = Field(default=None, min_length=1)
    confidence_score: int | None = Field(default=None, ge=0, le=100)
    product_tags: list[str] | None = None
    service_tags: list[str] | None = None


class RedFlagSynonymUpsertRequest(BaseModel):
    scope: str = Field(min_length=1, max_length=32)
    raw_value: str = Field(min_length=1, max_length=255)
    canonical_value: str = Field(min_length=1, max_length=128)
    apply_existing: bool = True


class RedFlagSynonymUpdateRequest(BaseModel):
    scope: str | None = Field(default=None, min_length=1, max_length=32)
    raw_value: str | None = Field(default=None, min_length=1, max_length=255)
    canonical_value: str | None = Field(default=None, min_length=1, max_length=128)
    is_active: bool | None = None
    apply_existing: bool = False


class CatalogAssistantChatRequest(BaseModel):
    business_unit_id: int = Field(ge=1)
    message: str = Field(min_length=1, max_length=4000)


class ExposureQuestionRequest(BaseModel):
    tenant_id: int = Field(ge=1)
    question: str = Field(min_length=1, max_length=4000)
    filter_overrides: dict[str, object] = Field(default_factory=dict)
    seed_limit: int = Field(default=8, ge=1, le=25)
    hops: int = Field(default=2, ge=1, le=5)
    max_nodes: int = Field(default=500, ge=10, le=2000)
    max_edges: int = Field(default=2000, ge=10, le=5000)
    include_surrogates: bool = True
    include_ofac_matches: bool = True
    include_txn_flow: bool = True
    include_graph: bool = True

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required.")

ENABLE_HTTPS_REDIRECT = os.environ.get("ENABLE_HTTPS_REDIRECT", "false").strip().lower() in {"1", "true", "yes", "on"}
SESSION_HTTPS_ONLY = os.environ.get("SESSION_HTTPS_ONLY", "false").strip().lower() in {"1", "true", "yes", "on"}

app = FastAPI()
if ENABLE_HTTPS_REDIRECT:
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(AuthContextMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=SESSION_HTTPS_ONLY,
    same_site="lax",
    max_age=60 * 60 * 8,
)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


def get_db() -> Session:
    return SessionLocal()


def _ensure_selection_table() -> None:
    inspector = inspect(engine)
    if not inspector.has_table("trf_selections"):
        TenantRedFlagSelection.__table__.create(bind=engine, checkfirst=True)


def _ensure_tenant_red_flag_table() -> None:
    inspector = inspect(engine)
    if not inspector.has_table("trf_red_flags"):
        TenantRedFlag.__table__.create(bind=engine, checkfirst=True)


def is_authenticated(request: Request) -> bool:
    return "user" in request.session or "user_email" in request.session


def _session_user_email(request: Request) -> str | None:
    user_email = request.session.get("user_email") or request.session.get("user")
    if not user_email:
        return None
    return str(user_email).strip().lower()


def _is_platform_admin_user(db: Session, email: str | None) -> bool:
    if not email:
        return False

    user_row = db.query(AppUser.id).filter(func.lower(AppUser.email) == email.lower()).first()
    if not user_row:
        return False
    user_id = int(user_row[0])

    role_row = db.query(Role.id).filter(Role.code == "application_admin").first()
    if not role_row:
        return False
    role_id = int(role_row[0])

    return (
        db.query(PlatformUserRole.id)
        .filter(PlatformUserRole.app_user_id == user_id, PlatformUserRole.role_id == role_id)
        .first()
        is not None
    )


def _get_user_id_by_email(db: Session, email: str) -> int | None:
    row = db.query(AppUser.id).filter(func.lower(AppUser.email) == email.lower()).first()
    return int(row[0]) if row else None


def _normalize_tags(tags: list[str] | None) -> list[str]:
    if not tags:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in tags:
        v = str(raw).strip()
        if not v:
            continue
        v = v[:64]
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
        if len(out) >= 10:
            break
    return out


def _parse_tags_json(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(v) for v in parsed if str(v).strip()]
    except Exception:
        pass
    return []


def _parse_string_list_json(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            out: list[str] = []
            seen: set[str] = set()
            for raw in parsed:
                code = str(raw).strip()
                if not code:
                    continue
                key = code.lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(code)
            return out
    except Exception:
        pass
    return []


def _norm_key(value: str | None) -> str:
    if value is None:
        return ""
    s = str(value).strip().lower()
    if not s:
        return ""
    out = []
    last_us = False
    for ch in s:
        if ch.isalnum():
            out.append(ch)
            last_us = False
            continue
        if not last_us:
            out.append("_")
            last_us = True
    normalized = "".join(out).strip("_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized


_CATALOG_ASSISTANT_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "has",
    "have",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "our",
    "that",
    "the",
    "their",
    "they",
    "this",
    "to",
    "we",
    "with",
}


def _catalog_assistant_tokens(text: str) -> list[str]:
    raw_tokens = re.findall(r"[a-z0-9]{2,}", (text or "").lower())
    deduped: list[str] = []
    seen: set[str] = set()
    for token in raw_tokens:
        if token in _CATALOG_ASSISTANT_STOP_WORDS:
            continue
        if token in seen:
            continue
        seen.add(token)
        deduped.append(token)
    return deduped[:24]


def _openai_catalog_assistant_enabled() -> bool:
    return bool(OPENAI_CATALOG_ASSISTANT_ENABLED and OPENAI_API_KEY and OPENAI_MODEL)


def _openai_catalog_assistant_reply(
    user_message: str,
    business_unit_name: str,
    candidates: list[dict[str, object]],
) -> tuple[str | None, list[str]]:
    if not _openai_catalog_assistant_enabled():
        return None, []
    if not candidates:
        return None, []

    payload_candidates: list[dict[str, object]] = []
    for row in candidates[:25]:
        payload_candidates.append(
            {
                "id": row.get("id"),
                "source": row.get("flag_source"),
                "source_name": row.get("source_name"),
                "category": row.get("category"),
                "severity": row.get("severity"),
                "text": str(row.get("text") or "")[:600],
                "product_tags": row.get("product_tags") or [],
                "service_tags": row.get("service_tags") or [],
            }
        )

    system_prompt = (
        "You are an AML red flag assistant for analysts. "
        "Only reason over the provided catalog candidates. "
        "Do not invent red flags not present in candidates. "
        "Return strict JSON with keys: assistant_message (string), recommended_ids (array of ids). "
        "Keep assistant_message concise and practical."
    )
    user_prompt = {
        "business_unit": business_unit_name,
        "analyst_message": user_message,
        "task": (
            "Identify the most relevant candidate red flags for this business unit context. "
            "Explain briefly and prioritize actionable review order."
        ),
        "candidates": payload_candidates,
    }

    body = {
        "model": OPENAI_MODEL,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_prompt)},
        ],
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OPENAI_CATALOG_ASSISTANT_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
        payload = json.loads(raw)
        content = (
            payload.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        parsed = json.loads(content) if content else {}
        assistant_message = str(parsed.get("assistant_message") or "").strip() or None
        recommended_ids = [
            str(v).strip()
            for v in (parsed.get("recommended_ids") or [])
            if str(v).strip()
        ]
        return assistant_message, recommended_ids
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError):
        return None, []


def _openai_exposure_assistant_enabled() -> bool:
    return bool(OPENAI_EXPOSURE_ASSISTANT_ENABLED and OPENAI_API_KEY and OPENAI_MODEL)


def _exposure_question_terms(question: str) -> list[str]:
    raw_tokens = re.findall(r"[a-z0-9]{2,}", (question or "").lower())
    out: list[str] = []
    seen: set[str] = set()
    for token in raw_tokens:
        if token in _CATALOG_ASSISTANT_STOP_WORDS:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out[:16]


def _load_exposure_intents_library() -> dict[str, object]:
    path = Path(EXPOSURE_INTENTS_CONFIG_PATH)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to load exposure intents config at {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError(f"Exposure intents config must be a JSON object: {path}")
    intents_raw = raw.get("intents")
    if not isinstance(intents_raw, list) or not intents_raw:
        raise RuntimeError(f"Exposure intents config requires a non-empty 'intents' list: {path}")

    intents: list[dict[str, object]] = []
    seen_codes: set[str] = set()
    for idx, row in enumerate(intents_raw, start=1):
        if not isinstance(row, dict):
            raise RuntimeError(f"Intent entry #{idx} must be an object: {path}")
        code = str(row.get("intent") or "").strip()
        description = str(row.get("description") or "").strip()
        query_plan_template = row.get("query_plan_template")
        if not code:
            raise RuntimeError(f"Intent entry #{idx} missing 'intent': {path}")
        if code in seen_codes:
            raise RuntimeError(f"Intent entry duplicate code '{code}': {path}")
        if not description:
            raise RuntimeError(f"Intent '{code}' missing 'description': {path}")
        if not isinstance(query_plan_template, dict):
            raise RuntimeError(f"Intent '{code}' missing object 'query_plan_template': {path}")
        seen_codes.add(code)
        intents.append(
            {
                "intent": code,
                "description": description,
                "priority": int(row.get("priority") or 0),
                "patterns": [str(v).strip().lower() for v in (row.get("patterns") or []) if str(v).strip()],
                "synonyms": [str(v).strip().lower() for v in (row.get("synonyms") or []) if str(v).strip()],
                "query_plan_template": query_plan_template,
                "assumptions": [str(v).strip() for v in (row.get("assumptions") or []) if str(v).strip()],
                "limitations": [str(v).strip() for v in (row.get("limitations") or []) if str(v).strip()],
                "top_seed_count": int(row.get("top_seed_count") or 3),
            }
        )

    default_intent = str(raw.get("default_intent") or "").strip()
    if not default_intent:
        raise RuntimeError(f"Exposure intents config missing 'default_intent': {path}")
    if default_intent not in seen_codes:
        raise RuntimeError(f"default_intent '{default_intent}' not found in intents list: {path}")

    return {
        "library_version": str(raw.get("library_version") or "unversioned"),
        "default_intent": default_intent,
        "intents": intents,
    }


_EXPOSURE_INTENTS_LIBRARY = _load_exposure_intents_library()


def _find_exposure_intent_definition(intent_code: str) -> dict[str, object]:
    for intent_row in _EXPOSURE_INTENTS_LIBRARY.get("intents", []):
        if isinstance(intent_row, dict) and str(intent_row.get("intent") or "") == intent_code:
            return intent_row
    raise KeyError(f"Intent definition not found: {intent_code}")


def _render_template_placeholders(value: object, context: dict[str, object]) -> object:
    if isinstance(value, str):
        rendered = value
        for key, ctx_val in context.items():
            rendered = rendered.replace("{" + key + "}", str(ctx_val))
        return rendered
    if isinstance(value, list):
        return [_render_template_placeholders(v, context) for v in value]
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for k, v in value.items():
            out[str(k)] = _render_template_placeholders(v, context)
        return out
    return value


def _intent_score(question_norm: str, question_terms: list[str], intent_row: dict[str, object]) -> int:
    score = 0
    patterns = [str(v) for v in (intent_row.get("patterns") or [])]
    synonyms = [str(v) for v in (intent_row.get("synonyms") or [])]
    for token in patterns:
        if token and token in question_norm:
            score += 140
    for token in synonyms:
        if token and token in question_norm:
            score += 70
    question_set = set(question_terms)
    synonyms_set = {str(v) for v in synonyms if str(v)}
    overlap = len(question_set.intersection(synonyms_set))
    score += overlap * 18
    score += int(intent_row.get("priority") or 0)
    return score


def _openai_exposure_intent_router_enabled() -> bool:
    return bool(OPENAI_EXPOSURE_INTENT_ROUTER_ENABLED and OPENAI_API_KEY and OPENAI_MODEL)


def _openai_assist_exposure_intent_mapping(
    *,
    question: str,
    rules_top: list[dict[str, object]],
) -> dict[str, object] | None:
    if not _openai_exposure_intent_router_enabled():
        return None
    allowed = [
        {
            "intent": str(row.get("intent") or ""),
            "description": str(row.get("description") or ""),
        }
        for row in (_EXPOSURE_INTENTS_LIBRARY.get("intents") or [])
        if isinstance(row, dict)
    ]
    if not allowed:
        return None
    system_prompt = (
        "You are an AML intent router. "
        "Select one or more intents only from the provided intent catalog. "
        "Return strict JSON with keys: intent_codes (array of strings), confidence (number 0..1), rationale (string). "
        "Do not output intents outside the catalog."
    )
    user_prompt = {
        "question": question,
        "intent_catalog": allowed,
        "rules_top_candidates": rules_top[:5],
        "task": "Map the question to the best intent or combination of intents for exposure analysis.",
    }
    body = {
        "model": OPENAI_MODEL,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_prompt)},
        ],
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_EXPOSURE_INTENT_ROUTER_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
        payload = json.loads(raw)
        content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = json.loads(content) if content else {}
        intent_codes_raw = parsed.get("intent_codes")
        confidence_raw = parsed.get("confidence")
        rationale = str(parsed.get("rationale") or "").strip()
        valid_codes: list[str] = []
        allowed_codes = {
            str(row.get("intent") or "")
            for row in (_EXPOSURE_INTENTS_LIBRARY.get("intents") or [])
            if isinstance(row, dict)
        }
        for code in (intent_codes_raw or []):
            c = str(code or "").strip()
            if not c or c not in allowed_codes:
                continue
            if c in valid_codes:
                continue
            valid_codes.append(c)
        if not valid_codes:
            return None
        confidence = float(confidence_raw) if confidence_raw is not None else 0.0
        if confidence < 0.0:
            confidence = 0.0
        if confidence > 1.0:
            confidence = 1.0
        return {
            "intent_codes": valid_codes,
            "confidence": confidence,
            "rationale": rationale,
        }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        return None


def _select_exposure_intent_route(question: str) -> dict[str, object]:
    question_norm = str(question or "").strip().lower()
    question_terms = _exposure_question_terms(question_norm)
    scored: list[tuple[int, dict[str, object]]] = []
    for row in _EXPOSURE_INTENTS_LIBRARY.get("intents", []):
        if not isinstance(row, dict):
            continue
        score = _intent_score(question_norm, question_terms, row)
        scored.append((score, row))
    scored.sort(key=lambda item: item[0], reverse=True)

    rules_top: list[dict[str, object]] = []
    for score, row in scored[:5]:
        rules_top.append(
            {
                "intent": str(row.get("intent") or ""),
                "description": str(row.get("description") or ""),
                "score": int(score),
            }
        )

    best_score = int(scored[0][0]) if scored else 0
    second_score = int(scored[1][0]) if len(scored) > 1 else 0
    normalized_score = min(1.0, float(best_score) / 300.0) if best_score > 0 else 0.0
    margin = float(best_score - second_score) / float(best_score + 1) if best_score > 0 else 0.0
    rule_confidence = max(0.0, min(1.0, (0.65 * normalized_score) + (0.35 * max(0.0, margin))))

    selected_rows: list[dict[str, object]] = []
    routing_mode = "rules_only"
    router_rationale = ""

    if scored and best_score > 0:
        selected_rows.append(scored[0][1])
        for score, row in scored[1:]:
            if score <= 0:
                continue
            # Add secondary intents only when they are materially close to the primary signal.
            if best_score > 0 and (float(score) / float(best_score)) >= 0.72:
                selected_rows.append(row)
            if len(selected_rows) >= 3:
                break

    needs_assist = (rule_confidence < EXPOSURE_INTENT_ROUTE_CONFIDENCE_THRESHOLD) or not selected_rows
    if needs_assist:
        llm_route = _openai_assist_exposure_intent_mapping(question=question, rules_top=rules_top)
        if llm_route:
            llm_codes = [str(v) for v in (llm_route.get("intent_codes") or []) if str(v)]
            llm_rows: list[dict[str, object]] = []
            for code in llm_codes:
                try:
                    llm_rows.append(_find_exposure_intent_definition(code))
                except KeyError:
                    continue
            if llm_rows:
                selected_rows = llm_rows[:3]
                routing_mode = "rules_plus_openai_router"
                router_rationale = str(llm_route.get("rationale") or "").strip()
                llm_conf = float(llm_route.get("confidence") or 0.0)
                rule_confidence = max(rule_confidence, max(0.0, min(1.0, llm_conf)))

    if not selected_rows:
        default_intent = str(_EXPOSURE_INTENTS_LIBRARY.get("default_intent") or "")
        selected_rows = [_find_exposure_intent_definition(default_intent)]
        routing_mode = "default_fallback"

    primary = selected_rows[0]
    return {
        "primary_intent": primary,
        "selected_intents": selected_rows,
        "routing_mode": routing_mode,
        "routing_confidence": rule_confidence,
        "routing_rationale": router_rationale,
        "rules_top_candidates": rules_top,
    }


def _merge_unique_strings(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        v = str(value or "").strip()
        if not v:
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


_TX_DIRECTION_SYNONYMS: dict[str, set[str]] = {
    "outbound": {
        "outbound",
        "outgoing",
        "sent",
        "egress",
        "to counterparty",
        "to counterparties",
        "payments to counterparty",
        "payments to counterparties",
        "payments out",
    },
    "inbound": {
        "inbound",
        "incoming",
        "received",
        "ingress",
        "from counterparty",
        "from counterparties",
        "payments from counterparty",
        "payments from counterparties",
        "payments in",
    },
}
_TX_MECHANISM_SYNONYMS: dict[str, set[str]] = {
    "wire": {"wire", "wires", "payments", "payment", "funds transfer", "transfer", "transfers", "swift", "mt103"},
    "ach": {"ach", "automated clearing house"},
    "online": {"online", "book transfer"},
    "branch": {"branch", "teller"},
    "atm": {"atm", "cash machine"},
}


def _openai_exposure_filter_mapper_enabled() -> bool:
    return bool(OPENAI_EXPOSURE_FILTER_MAPPER_ENABLED and OPENAI_API_KEY and OPENAI_MODEL)


def _catalog_list_values(catalog: dict[str, object], key: str) -> list[str]:
    values = catalog.get(key) if isinstance(catalog, dict) else None
    if not isinstance(values, list):
        return []
    return [str(v).strip() for v in values if str(v).strip()]


def _deterministic_transaction_filter_mapping(
    question: str,
    catalog: dict[str, object],
) -> tuple[dict[str, object], float, list[str]]:
    q = str(question or "").lower()
    reasons: list[str] = []
    mapped: dict[str, object] = {}
    confidence = 0.0

    directions = {v.lower(): v for v in _catalog_list_values(catalog, "directions")}
    mechanisms = {v.lower(): v for v in _catalog_list_values(catalog, "mechanisms")}

    for canonical, terms in _TX_DIRECTION_SYNONYMS.items():
        if canonical not in directions:
            continue
        if any(term in q for term in terms):
            mapped["direction"] = directions[canonical]
            reasons.append(f"Matched direction synonym set for `{canonical}`.")
            confidence += 0.4
            break

    for canonical, terms in _TX_MECHANISM_SYNONYMS.items():
        if canonical not in mechanisms:
            continue
        if any(term in q for term in terms):
            mapped["mechanism_contains"] = mechanisms[canonical]
            reasons.append(f"Matched mechanism synonym set for `{canonical}`.")
            confidence += 0.4
            break

    if any(term in q for term in ("outside us", "outside the us", "non-us", "non us", "outside united states")):
        if any(term in q for term in ("counterparty", "counterparties", "beneficiary", "beneficiaries", "recipient", "recipients")):
            mapped["outside_counterparty_jurisdiction"] = "US"
            reasons.append("Detected outside-US counterparty geography phrase.")
        elif any(term in q for term in ("customer", "customers", "client", "clients")):
            mapped["outside_customer_country_code"] = "US"
            reasons.append("Detected outside-US customer geography phrase.")
        elif any(term in q for term in ("branch", "branches")):
            mapped["outside_branch_country_code"] = "US"
            reasons.append("Detected outside-US branch geography phrase.")
        elif any(term in q for term in ("transaction", "transactions", "payment", "payments", "activity", "transfer", "transfers")):
            mapped["outside_country_code_2"] = "US"
            reasons.append("Detected outside-US transaction geography phrase.")
        else:
            reasons.append("Detected outside-US phrase without a clear filter dimension.")
        confidence += 0.25

    if any(term in q for term in ("wire", "wires", "payments", "payment")) and "mechanism_contains" not in mapped:
        mapped["aml_classification_contains"] = "External Funds Transfer"
        reasons.append("Fallback classification mapping for payment-like language.")
        confidence += 0.15

    return mapped, min(1.0, confidence), reasons


def _openai_map_transaction_filters(
    *,
    question: str,
    catalog: dict[str, object],
    deterministic_mapped: dict[str, object],
    deterministic_reasons: list[str],
) -> dict[str, object] | None:
    if not _openai_exposure_filter_mapper_enabled():
        return None

    payload = {
        "question": question,
        "allowed_values": {
            "directions": _catalog_list_values(catalog, "directions"),
            "mechanisms": _catalog_list_values(catalog, "mechanisms"),
            "aml_classifications": _catalog_list_values(catalog, "aml_classifications"),
            "country_codes_2": _catalog_list_values(catalog, "country_codes_2"),
            "counterparty_jurisdictions": _catalog_list_values(catalog, "counterparty_jurisdictions"),
            "customer_country_codes": _catalog_list_values(catalog, "customer_country_codes"),
            "branch_country_codes": _catalog_list_values(catalog, "branch_country_codes"),
        },
        "deterministic_candidate": deterministic_mapped,
        "deterministic_reasons": deterministic_reasons,
    }
    system_prompt = (
        "You map AML analyst language to structured transaction filters. "
        "Use only allowed values. "
        "Return strict JSON with keys: filters (object), confidence (number 0..1), rationale (string). "
        "filters may include direction, mechanism_contains, aml_classification_contains, outside_country_code_2, "
        "outside_counterparty_jurisdiction, counterparty_jurisdiction, outside_customer_country_code, "
        "customer_country_code, outside_branch_country_code, branch_country_code, account_type_contains, "
        "account_name_contains, customer_segment_contains, customer_business_unit, branch_type_contains. "
        "Map phrases like 'counterparties outside the US' to outside_counterparty_jurisdiction, "
        "not outside_country_code_2."
    )
    req_body = {
        "model": OPENAI_MODEL,
        "temperature": 0.0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload)},
        ],
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(req_body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_EXPOSURE_FILTER_MAPPER_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
        parsed = json.loads(raw)
        content = parsed.get("choices", [{}])[0].get("message", {}).get("content", "")
        out = json.loads(content) if content else {}
        filters = out.get("filters") if isinstance(out, dict) else None
        confidence = float(out.get("confidence") or 0.0) if isinstance(out, dict) else 0.0
        rationale = str(out.get("rationale") or "").strip() if isinstance(out, dict) else ""
        if not isinstance(filters, dict):
            return None
        return {
            "filters": filters,
            "confidence": max(0.0, min(1.0, confidence)),
            "rationale": rationale,
        }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        return None


def _validate_transaction_filter_mapping(filters: dict[str, object], catalog: dict[str, object]) -> dict[str, object]:
    valid: dict[str, object] = {}
    direction = str(filters.get("direction") or "").strip()
    if direction:
        direction_map = {v.lower(): v for v in _catalog_list_values(catalog, "directions")}
        resolved = direction_map.get(direction.lower())
        if resolved:
            valid["direction"] = resolved

    mechanism = str(filters.get("mechanism_contains") or "").strip()
    if mechanism:
        valid["mechanism_contains"] = mechanism

    aml = str(filters.get("aml_classification_contains") or "").strip()
    if aml:
        valid["aml_classification_contains"] = aml

    outside_cc = str(filters.get("outside_country_code_2") or "").strip().upper()
    if outside_cc:
        cc_map = {v.upper(): v.upper() for v in _catalog_list_values(catalog, "country_codes_2")}
        resolved_cc = cc_map.get(outside_cc)
        if resolved_cc:
            valid["outside_country_code_2"] = resolved_cc

    for source_key, catalog_key in (
        ("outside_counterparty_jurisdiction", "counterparty_jurisdictions"),
        ("counterparty_jurisdiction", "counterparty_jurisdictions"),
        ("outside_customer_country_code", "customer_country_codes"),
        ("customer_country_code", "customer_country_codes"),
        ("outside_branch_country_code", "branch_country_codes"),
        ("branch_country_code", "branch_country_codes"),
    ):
        raw = str(filters.get(source_key) or "").strip().upper()
        if not raw:
            continue
        allowed = {v.upper(): v.upper() for v in _catalog_list_values(catalog, catalog_key)}
        resolved = allowed.get(raw)
        if resolved:
            valid[source_key] = resolved

    for text_key in (
        "account_type_contains",
        "account_name_contains",
        "customer_segment_contains",
        "customer_business_unit",
        "branch_type_contains",
    ):
        raw = str(filters.get(text_key) or "").strip()
        if raw:
            valid[text_key] = raw
    return valid


def _outside_us_phrase_present(question: str) -> bool:
    q = str(question or "").lower()
    return any(term in q for term in ("outside us", "outside the us", "non-us", "non us", "outside united states"))


def _outside_us_dimension_hints(question: str) -> list[str]:
    q = str(question or "").lower()
    dimension_words = {
        "transaction": ("transaction", "transactions", "payment", "payments", "activity", "transfer", "transfers"),
        "counterparty": ("counterparty", "counterparties", "beneficiary", "beneficiaries", "recipient", "recipients"),
        "customer": ("customer", "customers", "client", "clients"),
        "branch": ("branch", "branches"),
    }
    return [
        dimension
        for dimension, words in dimension_words.items()
        if any(word in q for word in words)
    ]


def _outside_us_clarification(question: str, applied_filters: dict[str, object]) -> dict[str, object] | None:
    if not _outside_us_phrase_present(question):
        return None
    matched_dimensions = _outside_us_dimension_hints(question)
    dimension_filter_keys = {
        "outside_country_code_2",
        "outside_counterparty_jurisdiction",
        "outside_customer_country_code",
        "outside_branch_country_code",
    }
    applied_dimension_filters = [
        key
        for key in dimension_filter_keys
        if applied_filters.get(key)
    ]
    if len(matched_dimensions) == 1 and len(applied_dimension_filters) == 1:
        return None
    if len(matched_dimensions) > 1 and len(applied_dimension_filters) == 1:
        return None
    if applied_dimension_filters:
        return None
    return {
        "status": "needs_clarification",
        "question": "When you say outside the US, which dimension should the filter apply to?",
        "reason": "The phrase outside the US can refer to transaction country, counterparty jurisdiction, customer country, or branch country.",
        "choices": [
            {
                "label": "Counterparty jurisdiction",
                "filters": {"outside_counterparty_jurisdiction": "US"},
                "description": "Return payments where the counterparty jurisdiction is not US.",
            },
            {
                "label": "Transaction country",
                "filters": {"outside_country_code_2": "US"},
                "description": "Return payments where the transaction country code is not US.",
            },
            {
                "label": "Customer country",
                "filters": {"outside_customer_country_code": "US"},
                "description": "Return payments linked to customers whose country is not US.",
            },
            {
                "label": "Branch country",
                "filters": {"outside_branch_country_code": "US"},
                "description": "Return payments linked to branches whose country is not US.",
            },
        ],
    }


_FILTER_INTERPRETATION_LABELS: dict[str, tuple[str, str, str]] = {
    "direction": ("transaction", "direction", "equals"),
    "mechanism_contains": ("transaction", "mechanism", "contains"),
    "aml_classification_contains": ("transaction", "aml_classification", "contains"),
    "outside_country_code_2": ("transaction", "country_code_2", "outside"),
    "outside_counterparty_jurisdiction": ("counterparty", "jurisdiction", "outside"),
    "counterparty_jurisdiction": ("counterparty", "jurisdiction", "equals"),
    "outside_customer_country_code": ("customer", "country_code", "outside"),
    "customer_country_code": ("customer", "country_code", "equals"),
    "outside_branch_country_code": ("branch", "country_code", "outside"),
    "branch_country_code": ("branch", "country_code", "equals"),
    "account_type_contains": ("account", "account_type", "contains"),
    "account_name_contains": ("account", "account_name", "contains"),
    "customer_segment_contains": ("customer", "segment", "contains"),
    "customer_business_unit": ("customer", "business_unit", "equals"),
    "branch_type_contains": ("branch", "branch_type", "contains"),
}


def _interpreted_filters_from_applied(applied_filters: dict[str, object] | None) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    if not isinstance(applied_filters, dict):
        return out
    for key, value in applied_filters.items():
        if value is None or value == "":
            continue
        label = _FILTER_INTERPRETATION_LABELS.get(str(key))
        if not label:
            continue
        dimension, field, operator = label
        out.append(
            {
                "source_parameter": str(key),
                "dimension": dimension,
                "field": field,
                "operator": operator,
                "value": value,
            }
        )
    return out


def _build_interpreted_query(
    *,
    question: str,
    selected_intents: list[dict[str, object]],
    seed_candidates: list[dict[str, object]],
    tx_mapping_info: dict[str, object] | None,
    clarification: dict[str, object] | None = None,
) -> dict[str, object]:
    primary_seed = seed_candidates[0] if seed_candidates else {}
    applied_filters = (
        tx_mapping_info.get("applied_filters")
        if isinstance(tx_mapping_info, dict) and isinstance(tx_mapping_info.get("applied_filters"), dict)
        else {}
    )
    filters = _interpreted_filters_from_applied(applied_filters)
    subject = {
        "node_id": str(primary_seed.get("node_id") or ""),
        "node_type": str(primary_seed.get("node_type") or ""),
        "business_key": str(primary_seed.get("business_key") or ""),
        "label": str(primary_seed.get("label") or ""),
    }
    parts: list[str] = []
    if subject.get("label"):
        parts.append(f"subject `{subject['label']}`")
    if filters:
        parts.append(
            "filters "
            + ", ".join(
                f"{f['dimension']}.{f['field']} {f['operator']} {f['value']}"
                for f in filters
            )
        )
    natural_language = "Interpreted as " + "; ".join(parts) + "." if parts else "No executable interpretation was produced."
    return {
        "status": "needs_clarification" if clarification else "ready_to_run",
        "question": question,
        "subject": subject,
        "intents": [str(row.get("intent") or "") for row in selected_intents],
        "filters": filters,
        "filter_mapping": tx_mapping_info or {},
        "natural_language": natural_language,
        "clarification": clarification,
    }


def _normalize_transaction_filters_for_question(
    *,
    connection: TenantDataHubConnection,
    question: str,
    base_params: dict[str, object],
    filter_overrides: dict[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    catalog = _proxy_data_hub_json(connection, "/api/graph/transaction-filter-catalog", {})
    deterministic_filters, deterministic_confidence, deterministic_reasons = _deterministic_transaction_filter_mapping(
        question,
        catalog,
    )
    normalized = dict(base_params)
    deterministic_valid = _validate_transaction_filter_mapping(deterministic_filters, catalog)
    has_filter_overrides = isinstance(filter_overrides, dict) and bool(filter_overrides)
    ambiguous_outside_us = (
        _outside_us_phrase_present(question)
        and not _outside_us_dimension_hints(question)
        and not has_filter_overrides
    )
    if ambiguous_outside_us:
        normalized.pop("outside_country_code_2", None)
    normalized.update(deterministic_valid)
    if "outside_counterparty_jurisdiction" in deterministic_valid and "outside_country_code_2" in normalized:
        normalized.pop("outside_country_code_2", None)
    if "outside_customer_country_code" in deterministic_valid and "outside_country_code_2" in normalized:
        normalized.pop("outside_country_code_2", None)
    if "outside_branch_country_code" in deterministic_valid and "outside_country_code_2" in normalized:
        normalized.pop("outside_country_code_2", None)
    override_filters = _validate_transaction_filter_mapping(
        filter_overrides if isinstance(filter_overrides, dict) else {},
        catalog,
    )
    if override_filters:
        normalized.update(override_filters)
        if any(
            key in override_filters
            for key in ("outside_counterparty_jurisdiction", "outside_customer_country_code", "outside_branch_country_code")
        ):
            normalized.pop("outside_country_code_2", None)
    mode = "deterministic"
    confidence = deterministic_confidence
    rationale = "; ".join(deterministic_reasons)

    if confidence < EXPOSURE_FILTER_MAPPER_CONFIDENCE_THRESHOLD and not ambiguous_outside_us:
        llm = _openai_map_transaction_filters(
            question=question,
            catalog=catalog,
            deterministic_mapped=deterministic_filters,
            deterministic_reasons=deterministic_reasons,
        )
        if llm:
            llm_filters = _validate_transaction_filter_mapping(
                llm.get("filters") if isinstance(llm.get("filters"), dict) else {},
                catalog,
            )
            if llm_filters:
                normalized.update(llm_filters)
                if "outside_counterparty_jurisdiction" in llm_filters and "outside_country_code_2" in normalized:
                    normalized.pop("outside_country_code_2", None)
                if "outside_customer_country_code" in llm_filters and "outside_country_code_2" in normalized:
                    normalized.pop("outside_country_code_2", None)
                if "outside_branch_country_code" in llm_filters and "outside_country_code_2" in normalized:
                    normalized.pop("outside_country_code_2", None)
                mode = "openai_mapper"
                confidence = max(confidence, float(llm.get("confidence") or 0.0))
                rationale = str(llm.get("rationale") or rationale)

    mapping_info = {
        "mode": mode,
        "confidence": max(0.0, min(1.0, confidence)),
        "rationale": rationale,
        "deterministic_filters": deterministic_filters,
        "override_filters": override_filters,
        "applied_filters": {
            k: normalized.get(k)
            for k in (
                "direction",
                "mechanism_contains",
                "aml_classification_contains",
                "outside_country_code_2",
                "outside_counterparty_jurisdiction",
                "counterparty_jurisdiction",
                "outside_customer_country_code",
                "customer_country_code",
                "outside_branch_country_code",
                "branch_country_code",
                "account_type_contains",
                "account_name_contains",
                "customer_segment_contains",
                "customer_business_unit",
                "branch_type_contains",
            )
        },
    }
    return normalized, mapping_info


def _select_exposure_intent_definition(question: str) -> dict[str, object]:
    route = _select_exposure_intent_route(question)
    primary = route.get("primary_intent")
    if isinstance(primary, dict):
        return primary
    default_intent = str(_EXPOSURE_INTENTS_LIBRARY.get("default_intent") or "")
    return _find_exposure_intent_definition(default_intent)


def _build_exposure_query_plan_from_intent(
    *,
    intent_row: dict[str, object],
    question: str,
    seed_limit: int,
    hops: int,
    max_nodes: int,
    max_edges: int,
    include_surrogates: bool,
    include_ofac_matches: bool,
    include_txn_flow: bool,
) -> dict[str, object]:
    template = deepcopy(intent_row.get("query_plan_template") or {})
    context = {
        "question": question,
        "seed_limit": int(seed_limit),
        "hops": int(hops),
        "max_nodes": int(max_nodes),
        "max_edges": int(max_edges),
        "include_surrogates": str(bool(include_surrogates)).lower(),
        "include_ofac_matches": str(bool(include_ofac_matches)).lower(),
        "include_txn_flow": str(bool(include_txn_flow)).lower(),
    }
    rendered = _render_template_placeholders(template, context)
    query_plan = rendered if isinstance(rendered, dict) else {}
    query_plan["intent"] = str(intent_row.get("intent") or "")
    query_plan["intent_description"] = str(intent_row.get("description") or "")
    query_plan["terms"] = _exposure_question_terms(question)
    query_plan["intent_library_version"] = str(_EXPOSURE_INTENTS_LIBRARY.get("library_version") or "")
    return query_plan


def _query_plan_step_by_name(query_plan: dict[str, object], step_name: str) -> dict[str, object] | None:
    steps = query_plan.get("steps")
    if not isinstance(steps, list):
        return None
    for step in steps:
        if not isinstance(step, dict):
            continue
        if str(step.get("name") or "").strip() == step_name:
            return step
    return None


def _merge_graph_payloads(base_payload: dict[str, object], add_payload: dict[str, object]) -> dict[str, object]:
    out = deepcopy(base_payload if isinstance(base_payload, dict) else {})
    out_elements = out.get("elements") if isinstance(out.get("elements"), dict) else {}
    out_nodes = out_elements.get("nodes") if isinstance(out_elements.get("nodes"), list) else []
    out_edges = out_elements.get("edges") if isinstance(out_elements.get("edges"), list) else []

    node_map: dict[str, dict[str, object]] = {}
    for n in out_nodes:
        if not isinstance(n, dict):
            continue
        data = n.get("data")
        if not isinstance(data, dict):
            continue
        node_id = str(data.get("id") or "")
        if not node_id:
            continue
        node_map[node_id] = n

    edge_map: dict[str, dict[str, object]] = {}
    for e in out_edges:
        if not isinstance(e, dict):
            continue
        data = e.get("data")
        if not isinstance(data, dict):
            continue
        edge_id = str(data.get("id") or "")
        if not edge_id:
            continue
        edge_map[edge_id] = e

    add_elements = add_payload.get("elements") if isinstance(add_payload, dict) else None
    add_nodes = add_elements.get("nodes") if isinstance(add_elements, dict) and isinstance(add_elements.get("nodes"), list) else []
    add_edges = add_elements.get("edges") if isinstance(add_elements, dict) and isinstance(add_elements.get("edges"), list) else []

    for n in add_nodes:
        if not isinstance(n, dict):
            continue
        data = n.get("data")
        if not isinstance(data, dict):
            continue
        node_id = str(data.get("id") or "")
        if node_id and node_id not in node_map:
            node_map[node_id] = n

    for e in add_edges:
        if not isinstance(e, dict):
            continue
        data = e.get("data")
        if not isinstance(data, dict):
            continue
        edge_id = str(data.get("id") or "")
        if edge_id and edge_id not in edge_map:
            edge_map[edge_id] = e

    merged_nodes = list(node_map.values())
    merged_edges = list(edge_map.values())
    out["elements"] = {"nodes": merged_nodes, "edges": merged_edges}
    out["node_count"] = len(merged_nodes)
    out["edge_count"] = len(merged_edges)
    if not str(out.get("center_node") or "").strip():
        out["center_node"] = str(add_payload.get("center_node") or "")
    return out


def _parse_node_id(node_id: str) -> tuple[str, str]:
    raw = str(node_id or "").strip()
    if ":" not in raw:
        return "", ""
    node_type, business_key = raw.split(":", 1)
    return node_type.strip(), business_key.strip()


def _transaction_node_ids_from_rows(rows: list[dict[str, object]]) -> set[str]:
    out: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        account_key = str(row.get("account_key") or "").strip()
        counterparty_key = str(row.get("counterparty_account_key") or "").strip()
        if account_key:
            out.add(f"Account:{account_key}")
        if counterparty_key:
            out.add(f"CounterpartyAccount:{counterparty_key}")
    return out


def _seed_type_priority(node_type: str) -> int:
    t = str(node_type or "").strip()
    if t == "Customer":
        return 100
    if t == "Account":
        return 90
    if t == "CounterpartyAccount":
        return 80
    if t == "PanamaNode":
        return 40
    if t == "OfacSdn":
        return 30
    return 10


def _ordered_seed_candidates(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    def _score(row: dict[str, object]) -> float:
        node_type = str(row.get("node_type") or "")
        base = int(row.get("score") or 0)
        return float(base + _seed_type_priority(node_type))

    return sorted(
        [r for r in rows if isinstance(r, dict)],
        key=_score,
        reverse=True,
    )


def _summarize_exposure_graph(seed: dict[str, object], graph_payload: dict[str, object]) -> dict[str, object]:
    elements = graph_payload.get("elements") if isinstance(graph_payload, dict) else None
    nodes_raw = elements.get("nodes") if isinstance(elements, dict) else []
    edges_raw = elements.get("edges") if isinstance(elements, dict) else []
    nodes = nodes_raw if isinstance(nodes_raw, list) else []
    edges = edges_raw if isinstance(edges_raw, list) else []

    node_type_counts: dict[str, int] = {}
    edge_type_counts: dict[str, int] = {}
    node_lookup: dict[str, dict[str, object]] = {}

    for n in nodes:
        if not isinstance(n, dict):
            continue
        data = n.get("data")
        if not isinstance(data, dict):
            continue
        node_id = str(data.get("id") or "")
        node_type = str(data.get("node_type") or "Unknown")
        node_lookup[node_id] = data
        node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1

    key_relationships: list[dict[str, object]] = []
    for e in edges:
        if not isinstance(e, dict):
            continue
        data = e.get("data")
        if not isinstance(data, dict):
            continue
        edge_type = str(data.get("edge_type") or "EDGE")
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1

        if edge_type not in {"POTENTIAL_OFAC_MATCH", "PANAMA_RELATIONSHIP", "TXN_FLOW", "TXN_FLOW_SELF"}:
            continue
        src = str(data.get("source") or "")
        dst = str(data.get("target") or "")
        src_data = node_lookup.get(src, {})
        dst_data = node_lookup.get(dst, {})
        key_relationships.append(
            {
                "edge_type": edge_type,
                "source": src,
                "source_label": str(src_data.get("label") or src),
                "source_type": str(src_data.get("node_type") or ""),
                "target": dst,
                "target_label": str(dst_data.get("label") or dst),
                "target_type": str(dst_data.get("node_type") or ""),
                "txn_count": int(data.get("txn_count") or 0),
                "total_amount": float(data.get("total_amount") or 0.0),
            }
        )
        if len(key_relationships) >= 12:
            break

    key_entities: list[dict[str, str]] = []
    for node_id, data in node_lookup.items():
        node_type = str(data.get("node_type") or "")
        if node_type not in {"OfacSdn", "PanamaNode", "CounterpartyAccount"}:
            continue
        key_entities.append(
            {
                "node_id": node_id,
                "node_type": node_type,
                "label": str(data.get("label") or node_id),
            }
        )
        if len(key_entities) >= 12:
            break

    return {
        "seed": {
            "node_id": str(seed.get("node_id") or ""),
            "node_type": str(seed.get("node_type") or ""),
            "label": str(seed.get("label") or ""),
            "business_key": str(seed.get("business_key") or ""),
            "matched_fields": seed.get("matched_fields") if isinstance(seed.get("matched_fields"), list) else [],
            "score": int(seed.get("score") or 0),
        },
        "snapshot_id": str(graph_payload.get("snapshot_id") or ""),
        "as_of_ts": str(graph_payload.get("as_of_ts") or ""),
        "node_count": int(graph_payload.get("node_count") or len(nodes)),
        "edge_count": int(graph_payload.get("edge_count") or len(edges)),
        "node_type_counts": node_type_counts,
        "edge_type_counts": edge_type_counts,
        "key_entities": key_entities,
        "key_relationships": key_relationships,
    }


def _deterministic_exposure_summary(
    question: str,
    intent: str,
    evidence: list[dict[str, object]],
) -> tuple[str, list[str]]:
    if not evidence:
        return (
            "No exposure graph evidence was returned for the current question. Refine entity names or identifiers and retry.",
            ["No seed entities produced graph evidence in this run."],
        )

    top = evidence[0]
    seed = top.get("seed") if isinstance(top.get("seed"), dict) else {}
    seed_label = str(seed.get("label") or seed.get("node_id") or "seed")
    node_count = int(top.get("node_count") or 0)
    edge_count = int(top.get("edge_count") or 0)
    edge_types = top.get("edge_type_counts") if isinstance(top.get("edge_type_counts"), dict) else {}
    ofac_matches = int(edge_types.get("POTENTIAL_OFAC_MATCH") or 0)
    panama_links = int(edge_types.get("PANAMA_RELATIONSHIP") or 0)
    txn_flows = int(edge_types.get("TXN_FLOW") or 0) + int(edge_types.get("TXN_FLOW_SELF") or 0)

    summary = (
        f"Intent `{intent}` evaluated against the question and grounded on the top exposure seed `{seed_label}`. "
        f"The retrieved subgraph includes {node_count} nodes and {edge_count} edges."
    )
    findings: list[str] = []
    if ofac_matches:
        findings.append(f"Detected {ofac_matches} potential OFAC match relationship(s) in the analyzed exposure graph.")
    if panama_links:
        findings.append(f"Detected {panama_links} Panama relationship edge(s) linked to the analyzed seed network.")
    if txn_flows:
        findings.append(f"Detected {txn_flows} transaction-flow edge(s), indicating cash movement pathways in scope.")
    if not findings:
        findings.append(
            "No sanctions/offshore/transaction-specialized edge types were found in the top subgraph; review nearby entities."
        )
    return summary, findings


def _openai_exposure_grounded_summary(
    *,
    question: str,
    intent: str,
    intent_description: str,
    query_plan: dict[str, object],
    evidence: list[dict[str, object]],
) -> dict[str, object] | None:
    if not _openai_exposure_assistant_enabled():
        return None
    if not evidence:
        return None

    compact_evidence: list[dict[str, object]] = []
    for row in evidence[:3]:
        compact_evidence.append(
            {
                "seed": row.get("seed"),
                "as_of_ts": row.get("as_of_ts"),
                "node_count": row.get("node_count"),
                "edge_count": row.get("edge_count"),
                "node_type_counts": row.get("node_type_counts"),
                "edge_type_counts": row.get("edge_type_counts"),
                "key_entities": row.get("key_entities"),
                "key_relationships": row.get("key_relationships"),
            }
        )

    system_prompt = (
        "You are an AML exposure copilot for analysts. "
        "You must only use the provided query plan and evidence. "
        "Do not invent facts. "
        "Return strict JSON with keys: summary, why_relevant, assumptions, limitations. "
        "assumptions and limitations must each be arrays of short strings."
    )
    user_prompt = {
        "question": question,
        "intent": intent,
        "intent_description": intent_description,
        "query_plan": query_plan,
        "evidence": compact_evidence,
    }

    body = {
        "model": OPENAI_MODEL,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_prompt)},
        ],
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_EXPOSURE_ASSISTANT_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
        payload = json.loads(raw)
        content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = json.loads(content) if content else {}
        summary = str(parsed.get("summary") or "").strip()
        why_relevant = str(parsed.get("why_relevant") or "").strip()
        assumptions_raw = parsed.get("assumptions")
        limitations_raw = parsed.get("limitations")
        assumptions = [str(v).strip() for v in (assumptions_raw or []) if str(v).strip()]
        limitations = [str(v).strip() for v in (limitations_raw or []) if str(v).strip()]
        if not summary:
            return None
        return {
            "summary": summary,
            "why_relevant": why_relevant,
            "assumptions": assumptions,
            "limitations": limitations,
        }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError):
        return None


_SCOPE_FALLBACK = {
    "category": "other_suspicious_activity",
    "product": "other_product",
    "service": "other_service",
}


def _get_user_scope(db: Session, user_email: str) -> tuple[int | None, bool, list[int]]:
    user_id = _get_user_id_by_email(db, user_email)
    if not user_id:
        return None, False, []

    is_platform_admin = _is_platform_admin_user(db, user_email)
    tenant_rows = (
        db.query(TenantUser.tenant_id)
        .filter(
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
        )
        .distinct()
        .order_by(TenantUser.tenant_id.asc())
        .all()
    )
    tenant_ids = [int(r[0]) for r in tenant_rows]
    return user_id, is_platform_admin, tenant_ids


def _operational_reports_for_user(
    db: Session,
    user_id: int,
    is_platform_admin: bool,
    tenant_ids: list[int],
) -> list[dict[str, str | list[str]]]:
    if is_platform_admin:
        return [
            {
                "code": code,
                "name": str(defn["name"]),
                "description": str(defn["description"]),
                "required_roles": list(defn["roles"]),  # type: ignore[arg-type]
            }
            for code, defn in OPERATIONAL_REPORT_DEFINITIONS.items()
        ]

    if not tenant_ids:
        return []

    rows = (
        db.query(Role.code)
        .join(TenantUserRole, TenantUserRole.role_id == Role.id)
        .join(TenantUser, TenantUser.id == TenantUserRole.tenant_user_id)
        .join(
            TenantModuleEntitlement,
            and_(
                TenantModuleEntitlement.tenant_id == TenantUser.tenant_id,
                TenantModuleEntitlement.module_code == "operational_reporting",
                TenantModuleEntitlement.status == "active",
            ),
        )
        .filter(
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
            TenantUser.tenant_id.in_(tenant_ids),
        )
        .all()
    )
    role_codes = {str(r[0]) for r in rows}

    output: list[dict[str, str | list[str]]] = []
    for code, defn in OPERATIONAL_REPORT_DEFINITIONS.items():
        required = set(defn["roles"])  # type: ignore[arg-type]
        if role_codes.intersection(required):
            output.append(
                {
                    "code": code,
                    "name": str(defn["name"]),
                    "description": str(defn["description"]),
                    "required_roles": list(defn["roles"]),  # type: ignore[arg-type]
                }
            )
    return output


def _run_users_by_role_report(db: Session, tenant_ids: list[int] | None = None) -> dict[str, object]:
    query = (
        db.query(TenantUser.tenant_id, AppUser.email, Role.code)
        .join(TenantUser, TenantUser.app_user_id == AppUser.id)
        .join(TenantUserRole, TenantUserRole.tenant_user_id == TenantUser.id)
        .join(Role, Role.id == TenantUserRole.role_id)
        .filter(TenantUser.status == "active")
    )
    if tenant_ids:
        query = query.filter(TenantUser.tenant_id.in_(tenant_ids))
    rows = query.order_by(TenantUser.tenant_id.asc(), AppUser.email.asc(), Role.code.asc()).all()

    users_by_tenant: dict[str, dict[str, list[str]]] = {}
    for tenant_id, email, role_code in rows:
        tenant_key = str(tenant_id)
        users_by_tenant.setdefault(tenant_key, {}).setdefault(str(email), []).append(str(role_code))
    return {
        "tenant_scope": "all" if tenant_ids is None else [int(t) for t in tenant_ids],
        "users_by_tenant": users_by_tenant,
    }


def _users_by_role_matrix(report_data: dict[str, object]) -> dict[str, object]:
    users_by_tenant = report_data.get("users_by_tenant")
    if not isinstance(users_by_tenant, dict):
        return {"roles": [], "rows": []}

    role_set: set[str] = set()
    rows: list[dict[str, object]] = []
    for tenant_key in sorted(users_by_tenant.keys(), key=lambda v: str(v)):
        tenant_users = users_by_tenant.get(tenant_key)
        if not isinstance(tenant_users, dict):
            continue
        for email in sorted(tenant_users.keys(), key=lambda v: str(v).lower()):
            raw_roles = tenant_users.get(email) or []
            role_list = sorted({str(r) for r in raw_roles if str(r).strip()})
            for code in role_list:
                role_set.add(code)
            rows.append(
                {
                    "tenant_id": str(tenant_key),
                    "email": str(email),
                    "roles": role_list,
                    "role_map": {code: True for code in role_list},
                }
            )

    roles = sorted(role_set)
    return {"roles": roles, "rows": rows}


def _run_module_entitlements_report(db: Session, tenant_ids: list[int] | None = None) -> dict[str, object]:
    query = db.query(
        TenantModuleEntitlement.tenant_id,
        Tenant.name,
        TenantModuleEntitlement.module_code,
        TenantModuleEntitlement.status,
        TenantModuleEntitlement.enabled_from,
        TenantModuleEntitlement.enabled_to,
    ).join(Tenant, Tenant.id == TenantModuleEntitlement.tenant_id)
    if tenant_ids:
        query = query.filter(TenantModuleEntitlement.tenant_id.in_(tenant_ids))
    rows = query.order_by(TenantModuleEntitlement.tenant_id.asc(), TenantModuleEntitlement.module_code.asc()).all()

    entitlements = [
        {
            "tenant_id": int(tenant_id),
            "tenant_name": str(tenant_name),
            "module_code": str(module_code),
            "status": str(status),
            "enabled_from": enabled_from.isoformat() if enabled_from else None,
            "enabled_to": enabled_to.isoformat() if enabled_to else None,
        }
        for tenant_id, tenant_name, module_code, status, enabled_from, enabled_to in rows
    ]
    return {
        "tenant_scope": "all" if tenant_ids is None else [int(t) for t in tenant_ids],
        "entitlements": entitlements,
    }


def _module_entitlements_matrix(report_data: dict[str, object]) -> dict[str, object]:
    entitlements = report_data.get("entitlements")
    if not isinstance(entitlements, list):
        return {"modules": [], "rows": []}

    module_set: set[str] = set()
    by_tenant: dict[int, dict[str, object]] = {}

    for item in entitlements:
        if not isinstance(item, dict):
            continue
        tenant_id_raw = item.get("tenant_id")
        module_code_raw = item.get("module_code")
        status_raw = item.get("status")
        if tenant_id_raw is None or module_code_raw is None:
            continue
        tenant_id = int(tenant_id_raw)
        tenant_name = str(item.get("tenant_name") or f"Tenant {tenant_id}")
        module_code = str(module_code_raw)
        status = str(status_raw or "")
        module_set.add(module_code)
        if tenant_id not in by_tenant:
            by_tenant[tenant_id] = {
                "tenant_id": tenant_id,
                "tenant_name": tenant_name,
                "module_map": {},
            }
        by_tenant[tenant_id]["module_map"][module_code] = status

    modules = sorted(module_set)
    rows = sorted(
        by_tenant.values(),
        key=lambda r: (str(r.get("tenant_name", "")).lower(), int(r.get("tenant_id", 0))),
    )
    return {"modules": modules, "rows": rows}


def _run_audit_events_report(
    db: Session,
    tenant_ids: list[int] | None = None,
    limit: int = 500,
) -> dict[str, object]:
    q = db.query(AuditEvent)
    if tenant_ids is not None:
        # Tenant-scoped users can see their tenant rows and global rows (tenant_id NULL) if present.
        q = q.filter((AuditEvent.tenant_id.is_(None)) | (AuditEvent.tenant_id.in_(tenant_ids)))

    rows = (
        q.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .all()
    )

    events: list[dict[str, object]] = []
    for row in rows:
        payload: object
        raw_payload = row.event_payload_json
        if raw_payload:
            try:
                payload = json.loads(raw_payload)
            except Exception:
                payload = raw_payload
        else:
            payload = {}
        events.append(
            {
                "id": int(row.id),
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "tenant_id": int(row.tenant_id) if row.tenant_id is not None else None,
                "module_code": row.module_code,
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": int(row.entity_id) if row.entity_id is not None else None,
                "actor_user_id": int(row.actor_user_id) if row.actor_user_id is not None else None,
                "actor_email": row.actor_email,
                "request_method": row.request_method,
                "request_path": row.request_path,
                "request_ip": row.request_ip,
                "payload": payload,
            }
        )

    return {
        "tenant_scope": "all" if tenant_ids is None else [int(t) for t in tenant_ids],
        "count": len(events),
        "events": events,
    }


def _run_red_flag_workspace_capabilities_by_role_report(
    db: Session,
    tenant_ids: list[int] | None = None,
) -> dict[str, object]:
    tenant_query = db.query(Tenant.id, Tenant.name)
    if tenant_ids:
        tenant_query = tenant_query.filter(Tenant.id.in_(tenant_ids))
    tenant_rows = tenant_query.order_by(Tenant.name.asc(), Tenant.id.asc()).all()

    rows: list[dict[str, object]] = []
    capability_set: set[str] = set()
    role_set: set[str] = set()

    for tenant_id_raw, tenant_name_raw in tenant_rows:
        tenant_id = int(tenant_id_raw)
        tenant_name = str(tenant_name_raw)
        workflow_payload, workflow_source = _get_active_workflow_payload(
            db,
            tenant_id,
            "red_flags",
            _RED_FLAGS_WORKFLOW_ENTITY_TYPE,
        )
        states = list(workflow_payload.get("states") or [])
        transitions = list(workflow_payload.get("transitions") or [])

        tenant_role_codes: set[str] = set()
        for transition in transitions:
            for role_code_raw in (transition.get("allowed_roles") or []):
                role_code = str(role_code_raw).strip()
                if role_code:
                    tenant_role_codes.add(role_code)

        for role_code in sorted(tenant_role_codes):
            role_set.add(role_code)
            role_caps = sorted(_workflow_user_capabilities(states, transitions, {role_code}))
            for cap in role_caps:
                capability_set.add(cap)
            rows.append(
                {
                    "tenant_id": tenant_id,
                    "tenant_name": tenant_name,
                    "role_code": role_code,
                    "workflow_source": workflow_source,
                    "capabilities": role_caps,
                    "capability_map": {cap: True for cap in role_caps},
                }
            )

    rows.sort(
        key=lambda r: (
            str(r.get("tenant_name", "")).lower(),
            str(r.get("role_code", "")).lower(),
        )
    )
    return {
        "tenant_scope": "all" if tenant_ids is None else [int(t) for t in tenant_ids],
        "roles": sorted(role_set),
        "capabilities": sorted(capability_set),
        "rows": rows,
    }


def _csv_text_from_dict_rows(fieldnames: list[str], rows: list[dict[str, object]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
    return output.getvalue()


def _export_operational_report_csv(
    db: Session,
    report_code: str,
    tenant_scope: list[int] | None,
) -> tuple[str, str]:
    if report_code == "users_by_role":
        report_data = _run_users_by_role_report(db, tenant_scope)
        matrix = _users_by_role_matrix(report_data)
        roles = [str(r) for r in (matrix.get("roles") or [])]
        rows_out: list[dict[str, object]] = []
        for row in (matrix.get("rows") or []):
            if not isinstance(row, dict):
                continue
            record: dict[str, object] = {
                "tenant_id": row.get("tenant_id"),
                "email": row.get("email"),
            }
            role_map = row.get("role_map") if isinstance(row.get("role_map"), dict) else {}
            for role in roles:
                record[role] = "X" if role_map.get(role) else ""
            rows_out.append(record)
        fieldnames = ["tenant_id", "email"] + roles
        return _csv_text_from_dict_rows(fieldnames, rows_out), "users_by_role"

    if report_code == "module_entitlements":
        report_data = _run_module_entitlements_report(db, tenant_scope)
        matrix = _module_entitlements_matrix(report_data)
        modules = [str(m) for m in (matrix.get("modules") or [])]
        rows_out: list[dict[str, object]] = []
        for row in (matrix.get("rows") or []):
            if not isinstance(row, dict):
                continue
            record: dict[str, object] = {
                "tenant_id": row.get("tenant_id"),
                "tenant_name": row.get("tenant_name"),
            }
            module_map = row.get("module_map") if isinstance(row.get("module_map"), dict) else {}
            for module_code in modules:
                record[module_code] = module_map.get(module_code, "")
            rows_out.append(record)
        fieldnames = ["tenant_id", "tenant_name"] + modules
        return _csv_text_from_dict_rows(fieldnames, rows_out), "module_entitlements"

    if report_code == "red_flag_workspace_capabilities":
        report_data = _run_red_flag_workspace_capabilities_by_role_report(db, tenant_scope)
        capabilities = [str(c) for c in (report_data.get("capabilities") or [])]
        rows_out: list[dict[str, object]] = []
        for row in (report_data.get("rows") or []):
            if not isinstance(row, dict):
                continue
            record: dict[str, object] = {
                "tenant_id": row.get("tenant_id"),
                "tenant_name": row.get("tenant_name"),
                "role_code": row.get("role_code"),
                "workflow_source": row.get("workflow_source"),
            }
            capability_map = row.get("capability_map") if isinstance(row.get("capability_map"), dict) else {}
            for capability in capabilities:
                record[capability] = "X" if capability_map.get(capability) else ""
            rows_out.append(record)
        fieldnames = ["tenant_id", "tenant_name", "role_code", "workflow_source"] + capabilities
        return _csv_text_from_dict_rows(fieldnames, rows_out), "red_flag_workspace_capabilities"

    raise HTTPException(status_code=400, detail=f"CSV export not supported for report_code: {report_code}")


def get_csrf_token(request: Request) -> str:
    csrf_token = request.session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = csrf_token
    return csrf_token


def validate_csrf(request: Request, csrf_token: str) -> None:
    session_token = request.session.get("csrf_token")
    if not session_token or not secrets.compare_digest(session_token, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def _hash_invite_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _issue_password_setup_invite(app_user: AppUser) -> tuple[str, datetime]:
    raw_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    app_user.invite_token_hash = _hash_invite_token(raw_token)
    app_user.invite_token_expires_at = expires_at
    return raw_token, expires_at


def _build_password_setup_url(token: str) -> str:
    configured_base = os.environ.get("AMLINSIGHTS_BASE_URL", "").strip().rstrip("/")
    path = f"/setup-password?token={token}"
    if configured_base:
        return f"{configured_base}{path}"
    return path


@app.get("/")
def hello_world(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "AML Insights",
            "heading": "Hello, World from FastAPI on Heroku!",
            "message": "The app is running and serving HTML with Jinja2 templates.",
            "is_authenticated": is_authenticated(request),
            "user": request.session.get("user"),
            "csrf_token": get_csrf_token(request),
        },
    )


@app.get("/login")
def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "title": "Login",
            "error": None,
            "has_users": has_users(),
            "csrf_token": get_csrf_token(request),
        },
    )


@app.get("/setup-password")
def setup_password_page(request: Request, token: str = Query(..., min_length=10)):
    db = get_db()
    try:
        token_hash = _hash_invite_token(token)
        user = (
            db.query(AppUser)
            .filter(
                AppUser.invite_token_hash == token_hash,
                AppUser.invite_token_expires_at.isnot(None),
            )
            .first()
        )
        now = datetime.now(timezone.utc)
        if (
            not user
            or not user.invite_token_expires_at
            or user.invite_token_expires_at.replace(tzinfo=timezone.utc) < now
        ):
            return templates.TemplateResponse(
                request=request,
                name="setup_password.html",
                context={
                    "title": "Set Password",
                    "error": "This setup link is invalid or has expired.",
                    "token": token,
                    "csrf_token": get_csrf_token(request),
                    "email": None,
                },
                status_code=400,
            )
        return templates.TemplateResponse(
            request=request,
            name="setup_password.html",
            context={
                "title": "Set Password",
                "error": None,
                "token": token,
                "csrf_token": get_csrf_token(request),
                "email": user.email,
            },
        )
    finally:
        db.close()


@app.post("/setup-password")
def setup_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    csrf_token: str = Form(...),
):
    validate_csrf(request, csrf_token)
    if not password:
        return templates.TemplateResponse(
            request=request,
            name="setup_password.html",
            context={
                "title": "Set Password",
                "error": "Password cannot be empty.",
                "token": token,
                "csrf_token": get_csrf_token(request),
                "email": None,
            },
            status_code=400,
        )
    if password != password_confirm:
        return templates.TemplateResponse(
            request=request,
            name="setup_password.html",
            context={
                "title": "Set Password",
                "error": "Passwords do not match.",
                "token": token,
                "csrf_token": get_csrf_token(request),
                "email": None,
            },
            status_code=400,
        )

    db = get_db()
    try:
        token_hash = _hash_invite_token(token)
        user = (
            db.query(AppUser)
            .filter(
                AppUser.invite_token_hash == token_hash,
                AppUser.invite_token_expires_at.isnot(None),
            )
            .first()
        )
        now = datetime.now(timezone.utc)
        if (
            not user
            or not user.invite_token_expires_at
            or user.invite_token_expires_at.replace(tzinfo=timezone.utc) < now
        ):
            return templates.TemplateResponse(
                request=request,
                name="setup_password.html",
                context={
                    "title": "Set Password",
                    "error": "This setup link is invalid or has expired.",
                    "token": token,
                    "csrf_token": get_csrf_token(request),
                    "email": None,
                },
                status_code=400,
            )

        user.password_hash = hash_password(password)
        user.invite_token_hash = None
        user.invite_token_expires_at = None
        _record_audit_event(
            db,
            module_code="auth",
            action="password_setup_completed",
            actor_user_id=int(user.id),
            actor_email=user.email,
            request=request,
            payload={"status": "success"},
        )
        db.commit()
        return RedirectResponse(url="/login", status_code=303)
    finally:
        db.close()


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    validate_csrf(request, csrf_token)
    login_id = username.strip().lower()
    db = get_db()

    try:
        app_user = db.query(AppUser).filter(func.lower(AppUser.email) == login_id).first()

        if app_user and app_user.password_hash and verify_password(password, app_user.password_hash):
            if needs_rehash(app_user.password_hash):
                app_user.password_hash = hash_password(password)
            _record_audit_event(
                db,
                module_code="auth",
                action="login_success",
                actor_user_id=int(app_user.id),
                actor_email=app_user.email,
                request=request,
                payload={"legacy_migration": False},
            )
            db.commit()
            request.session["user"] = app_user.email
            request.session["user_email"] = app_user.email
            return RedirectResponse(url="/dashboard", status_code=303)

        # Legacy fallback path: if user exists in old users table, migrate to app_users.
        legacy_user = db.query(User).filter(func.lower(User.username) == login_id).first()
        if legacy_user and verify_password(password, legacy_user.password_hash):
            migrated = app_user
            if not migrated:
                migrated = AppUser(
                    email=legacy_user.username.lower(),
                    password_hash=legacy_user.password_hash,
                    status="active",
                    created_at=datetime.now(timezone.utc),
                )
                db.add(migrated)
            else:
                migrated.password_hash = legacy_user.password_hash
            if needs_rehash(migrated.password_hash or ""):
                migrated.password_hash = hash_password(password)
            _record_audit_event(
                db,
                module_code="auth",
                action="login_success",
                actor_user_id=int(migrated.id),
                actor_email=migrated.email,
                request=request,
                payload={"legacy_migration": True},
            )
            db.commit()
            request.session["user"] = migrated.email
            request.session["user_email"] = migrated.email
            return RedirectResponse(url="/dashboard", status_code=303)

        _record_audit_event(
            db,
            module_code="auth",
            action="login_failed",
            actor_email=login_id,
            request=request,
            payload={"reason": "invalid_credentials"},
        )
        db.commit()
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "title": "Login",
            "error": "Invalid username or password.",
            "has_users": has_users(),
            "csrf_token": get_csrf_token(request),
        },
        status_code=401,
    )


@app.get("/dashboard")
def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    db = get_db()
    try:
        is_platform_admin = _is_platform_admin_user(db, user_email)
        has_red_flag_analyst = bool(
            user_email
            and _accessible_tenant_summaries_for_module_role(
                db,
                user_email,
                module_code="red_flags",
                role_code="red_flag_analyst",
            )
        )
        has_red_flag_approver = bool(
            user_email
            and _accessible_tenant_summaries_for_module_role(
                db,
                user_email,
                module_code="red_flags",
                role_code="red_flag_approver",
            )
        )
        has_read_only_audit = bool(
            user_email
            and _accessible_tenant_summaries_for_module_role(
                db,
                user_email,
                module_code="red_flags",
                role_code="read_only_audit",
            )
        )
        has_tenant_admin = bool(
            user_email
            and _accessible_tenant_summaries_for_role(
                db,
                user_email,
                role_code="tenant_admin",
            )
        )
        has_tenant_investigator = bool(
            user_email
            and _accessible_tenant_summaries_for_role(
                db,
                user_email,
                role_code="tenant_investigator",
            )
        )
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "title": "Dashboard",
            "user": request.session["user"],
            "csrf_token": get_csrf_token(request),
            "is_platform_admin": is_platform_admin,
            "has_red_flag_analyst": has_red_flag_analyst,
            "has_red_flag_approver": has_red_flag_approver,
            "has_read_only_audit": has_read_only_audit,
            "has_tenant_management_access": bool(is_platform_admin or has_tenant_admin),
            "has_red_flag_workspace_access": bool(
                is_platform_admin
                or has_tenant_admin
                or has_red_flag_analyst
                or has_red_flag_approver
                or has_read_only_audit
            ),
            "has_entity_search_access": bool(is_platform_admin or has_tenant_admin or has_tenant_investigator),
        },
    )


@app.get("/ui/templates/amlredflags")
def amlredflags_template_ui(request: Request):
    return RedirectResponse(url="/ui/red-flags/workspace", status_code=303)


@app.get("/ui/red-flags-management")
def red_flags_management_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/ui/red-flags/workspace", status_code=303)


@app.get("/ui/red-flags/workspace")
def red_flags_workspace_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    default_user_email = user_email or os.environ.get("AML_USER_EMAIL", "owner@amlinsights.local")
    default_tenant_id = os.environ.get("AML_TENANT_ID", "1")
    db = get_db()
    try:
        analyst_tenants = (
            _accessible_tenant_summaries_for_module_role(
                db,
                user_email,
                module_code="red_flags",
                role_code="red_flag_analyst",
            )
            if user_email
            else []
        )
        approver_tenants = (
            _accessible_tenant_summaries_for_module_role(
                db,
                user_email,
                module_code="red_flags",
                role_code="red_flag_approver",
            )
            if user_email
            else []
        )
        audit_tenants = (
            _accessible_tenant_summaries_for_module_role(
                db,
                user_email,
                module_code="red_flags",
                role_code="read_only_audit",
            )
            if user_email
            else []
        )
        has_access = bool(analyst_tenants or approver_tenants or audit_tenants)
        if not has_access:
            raise HTTPException(
                status_code=403,
                detail="Red Flags Workspace requires red_flag_analyst, red_flag_approver, or read_only_audit role.",
            )
        combined_tenants: list[dict[str, object]] = []
        seen_tenants: set[int] = set()
        for group in (analyst_tenants, approver_tenants, audit_tenants):
            for t in group:
                tenant_id = int(t["id"])
                if tenant_id in seen_tenants:
                    continue
                seen_tenants.add(tenant_id)
                combined_tenants.append(t)
        if combined_tenants:
            default_tenant_id = str(combined_tenants[0]["id"])
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="red_flags_workspace.html",
        context={
            "title": "Red Flags Workspace",
            "user": request.session["user"],
            "default_user_email": default_user_email,
            "default_tenant_id": default_tenant_id,
            "csrf_token": get_csrf_token(request),
        },
    )


@app.get("/ui/operational-reporting")
def operational_reporting_ui(
    request: Request,
    report_code: str | None = Query(default=None),
):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    if not user_email:
        return RedirectResponse(url="/login", status_code=303)

    reports: list[dict[str, str | list[str]]] = []
    report_result_json: str | None = None
    users_by_role_matrix: dict[str, object] | None = None
    module_entitlements_matrix: dict[str, object] | None = None
    red_flag_workspace_capabilities_matrix: dict[str, object] | None = None
    selected_report_name: str | None = None
    error: str | None = None
    tenant_scope: list[int] | None = None
    tenant_scope_names: list[str] = []
    is_platform_admin = False

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            error = f"Unknown user: {user_email}"
        else:
            tenant_scope = None if is_platform_admin else tenant_ids
            if not is_platform_admin and not tenant_ids:
                error = "No active tenant assignment found for this user."
            if tenant_ids:
                tenant_rows = (
                    db.query(Tenant.id, Tenant.name)
                    .filter(Tenant.id.in_(tenant_ids))
                    .order_by(Tenant.name.asc())
                    .all()
                )
                tenant_scope_names = [str(name) for _, name in tenant_rows]
            reports = _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)
            selected_report_name = next(
                (str(item["name"]) for item in reports if str(item.get("code")) == str(report_code)),
                None,
            )
            report_codes = {str(item["code"]) for item in reports}
            if report_code:
                if report_code not in report_codes:
                    error = "You are not authorized to run this report."
                elif report_code == "users_by_role":
                    users_by_role_report = _run_users_by_role_report(db, tenant_scope)
                    users_by_role_matrix = _users_by_role_matrix(users_by_role_report)
                    report_result_json = json.dumps(
                        users_by_role_report,
                        indent=2,
                        sort_keys=True,
                        default=str,
                    )
                elif report_code == "module_entitlements":
                    module_entitlements_report = _run_module_entitlements_report(db, tenant_scope)
                    module_entitlements_matrix = _module_entitlements_matrix(module_entitlements_report)
                    report_result_json = json.dumps(
                        module_entitlements_report,
                        indent=2,
                        sort_keys=True,
                        default=str,
                    )
                elif report_code == "audit_events":
                    report_result_json = json.dumps(
                        _run_audit_events_report(db, tenant_scope),
                        indent=2,
                        sort_keys=True,
                        default=str,
                    )
                elif report_code == "red_flag_workspace_capabilities":
                    red_flag_workspace_capabilities_matrix = _run_red_flag_workspace_capabilities_by_role_report(
                        db, tenant_scope
                    )
                    report_result_json = json.dumps(
                        red_flag_workspace_capabilities_matrix,
                        indent=2,
                        sort_keys=True,
                        default=str,
                    )
                else:
                    error = f"Unknown report_code: {report_code}"
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="operational_reporting.html",
        context={
            "title": "Operational Reporting",
            "user": request.session["user"],
            "user_email": user_email,
            "is_platform_admin": is_platform_admin,
            "tenant_scope": tenant_scope or [],
            "tenant_scope_names": tenant_scope_names,
            "reports": reports,
            "selected_report_code": report_code,
            "selected_report_name": selected_report_name,
            "report_result_json": report_result_json,
            "users_by_role_matrix": users_by_role_matrix,
            "module_entitlements_matrix": module_entitlements_matrix,
            "red_flag_workspace_capabilities_matrix": red_flag_workspace_capabilities_matrix,
            "error": error,
        },
    )


@app.get("/ui/admin/red-flags-curation")
def red_flags_curation_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    db = get_db()
    try:
        if not _is_platform_admin_user(db, user_email):
            raise HTTPException(status_code=403, detail="Application admin role required.")
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="red_flags_curation.html",
        context={
            "title": "Red Flags Curation",
            "user": request.session["user"],
        },
    )


@app.get("/ui/admin/red-flag-synonyms")
def red_flag_synonyms_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    db = get_db()
    try:
        if not _is_platform_admin_user(db, user_email):
            raise HTTPException(status_code=403, detail="Application admin role required.")
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="red_flag_synonyms.html",
        context={
            "title": "Red Flag Synonyms",
            "user": request.session["user"],
        },
    )


@app.get("/api/admin/red-flags")
def list_admin_red_flags(
    search: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=20, ge=1, le=1000),
    _: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        q = db.query(RedFlag)
        if search:
            needle = f"%{search.strip().lower()}%"
            q = q.filter(
                func.lower(RedFlag.text).like(needle)
                | func.lower(RedFlag.category).like(needle)
            )
        if category:
            q = q.filter(func.lower(RedFlag.category) == category.strip().lower())
        if severity:
            q = q.filter(func.lower(RedFlag.severity) == severity.strip().lower())
        rows = q.order_by(RedFlag.id.desc()).limit(limit).all()
        return {
            "success": True,
            "total": len(rows),
            "data": [
                {
                    "id": r.id,
                    "document_id": r.document_id,
                    "category": r.category,
                    "raw_category": r.raw_category,
                    "severity": r.severity,
                    "text": r.text,
                    "confidence_score": r.confidence_score,
                    "product_tags": _parse_tags_json(r.product_tags_json),
                    "service_tags": _parse_tags_json(r.service_tags_json),
                    "raw_product_tags": _parse_tags_json(r.raw_product_tags_json),
                    "raw_service_tags": _parse_tags_json(r.raw_service_tags_json),
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ],
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/admin/red-flags")
def create_admin_red_flag(
    request: Request,
    payload: AdminRedFlagCreateRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    try:
        red_flag = RedFlag(
            document_id=payload.document_id,
            category=payload.category.strip(),
            severity=payload.severity.strip(),
            text=payload.text.strip(),
            confidence_score=payload.confidence_score,
            product_tags_json=json.dumps(_normalize_tags(payload.product_tags), separators=(",", ":")),
            service_tags_json=json.dumps(_normalize_tags(payload.service_tags), separators=(",", ":")),
            created_at=now,
        )
        db.add(red_flag)
        db.commit()
        db.refresh(red_flag)
        _record_audit_event(
            db,
            module_code="red_flags_admin",
            action="red_flag_created",
            entity_type="red_flag",
            entity_id=int(red_flag.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"category": red_flag.category, "severity": red_flag.severity},
        )
        db.commit()
        return {
            "success": True,
            "data": {
                "id": red_flag.id,
                "document_id": red_flag.document_id,
                "category": red_flag.category,
                "raw_category": red_flag.raw_category,
                "severity": red_flag.severity,
                "text": red_flag.text,
                "confidence_score": red_flag.confidence_score,
                "product_tags": _parse_tags_json(red_flag.product_tags_json),
                "service_tags": _parse_tags_json(red_flag.service_tags_json),
                "raw_product_tags": _parse_tags_json(red_flag.raw_product_tags_json),
                "raw_service_tags": _parse_tags_json(red_flag.raw_service_tags_json),
                "created_at": red_flag.created_at.isoformat() if red_flag.created_at else None,
            },
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.patch("/api/admin/red-flags/{red_flag_id}")
def update_admin_red_flag(
    request: Request,
    red_flag_id: int,
    payload: AdminRedFlagUpdateRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        red_flag = db.query(RedFlag).filter(RedFlag.id == red_flag_id).first()
        if not red_flag:
            raise HTTPException(status_code=404, detail="Red flag not found.")

        if payload.category is not None:
            red_flag.category = payload.category.strip()
        if payload.severity is not None:
            red_flag.severity = payload.severity.strip()
        if payload.text is not None:
            red_flag.text = payload.text.strip()
        if payload.confidence_score is not None:
            red_flag.confidence_score = payload.confidence_score
        if payload.product_tags is not None:
            red_flag.product_tags_json = json.dumps(_normalize_tags(payload.product_tags), separators=(",", ":"))
        if payload.service_tags is not None:
            red_flag.service_tags_json = json.dumps(_normalize_tags(payload.service_tags), separators=(",", ":"))

        db.commit()
        db.refresh(red_flag)
        _record_audit_event(
            db,
            module_code="red_flags_admin",
            action="red_flag_updated",
            entity_type="red_flag",
            entity_id=int(red_flag.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"category": red_flag.category, "severity": red_flag.severity},
        )
        db.commit()
        return {
            "success": True,
            "data": {
                "id": red_flag.id,
                "document_id": red_flag.document_id,
                "category": red_flag.category,
                "raw_category": red_flag.raw_category,
                "severity": red_flag.severity,
                "text": red_flag.text,
                "confidence_score": red_flag.confidence_score,
                "product_tags": _parse_tags_json(red_flag.product_tags_json),
                "service_tags": _parse_tags_json(red_flag.service_tags_json),
                "raw_product_tags": _parse_tags_json(red_flag.raw_product_tags_json),
                "raw_service_tags": _parse_tags_json(red_flag.raw_service_tags_json),
                "created_at": red_flag.created_at.isoformat() if red_flag.created_at else None,
            },
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.delete("/api/admin/red-flags/{red_flag_id}")
def delete_admin_red_flag(
    request: Request,
    red_flag_id: int,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        red_flag = db.query(RedFlag).filter(RedFlag.id == red_flag_id).first()
        if not red_flag:
            raise HTTPException(status_code=404, detail="Red flag not found.")

        linked_count = (
            db.query(TenantRedFlagSelection.id)
            .filter(TenantRedFlagSelection.shared_red_flag_id == red_flag_id)
            .count()
        )
        if linked_count > 0:
            raise HTTPException(
                status_code=409,
                detail=f"Red flag is referenced by {linked_count} tenant selection rows and cannot be deleted.",
            )

        _record_audit_event(
            db,
            module_code="red_flags_admin",
            action="red_flag_deleted",
            entity_type="red_flag",
            entity_id=int(red_flag.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"category": red_flag.category, "severity": red_flag.severity},
        )
        db.delete(red_flag)
        db.commit()
        return {"success": True, "deleted": True, "id": red_flag_id}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/admin/red-flag-synonyms")
def list_red_flag_synonyms(
    scope: str | None = None,
    include_inactive: bool = False,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    q = db.query(RedFlagSynonym)
    if scope:
        norm_scope = scope.strip().lower()
        if norm_scope not in {"category", "product", "service"}:
            raise HTTPException(status_code=400, detail="scope must be one of: category, product, service")
        q = q.filter(RedFlagSynonym.scope == norm_scope)
    if not include_inactive:
        q = q.filter(RedFlagSynonym.is_active == True)  # noqa: E712
    total = q.count()
    rows = (
        q.order_by(RedFlagSynonym.scope.asc(), RedFlagSynonym.raw_value_key.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": [
            {
                "id": r.id,
                "scope": r.scope,
                "raw_value": r.raw_value,
                "raw_value_key": r.raw_value_key,
                "canonical_value": r.canonical_value,
                "is_active": bool(r.is_active),
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rows
        ],
    }


@app.get("/api/admin/red-flag-synonyms/candidates")
def list_red_flag_synonym_candidates(
    scope: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    norm_scope = scope.strip().lower()
    if norm_scope not in {"category", "product", "service"}:
        raise HTTPException(status_code=400, detail="scope must be one of: category, product, service")

    fallback = _SCOPE_FALLBACK[norm_scope]
    counts: dict[str, int] = {}
    examples: dict[str, str] = {}

    if norm_scope == "category":
        rows = (
            db.query(RedFlag.raw_category, func.count(RedFlag.id))
            .filter(
                RedFlag.raw_category.isnot(None),
                func.lower(RedFlag.category) == fallback,
            )
            .group_by(RedFlag.raw_category)
            .order_by(func.count(RedFlag.id).desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        total = (
            db.query(func.count())
            .select_from(
                db.query(RedFlag.raw_category)
                .filter(
                    RedFlag.raw_category.isnot(None),
                    func.lower(RedFlag.category) == fallback,
                )
                .group_by(RedFlag.raw_category)
                .subquery()
            )
            .scalar()
            or 0
        )
        data = []
        for raw_value, cnt in rows:
            raw_clean = str(raw_value or "").strip()
            if not raw_clean:
                continue
            data.append({"raw_value": raw_clean, "raw_value_key": _norm_key(raw_clean), "count": int(cnt)})
        return {
            "success": True,
            "scope": norm_scope,
            "fallback": fallback,
            "total": int(total),
            "limit": limit,
            "offset": offset,
            "data": data,
        }

    rows = (
        db.query(RedFlag.raw_product_tags_json, RedFlag.product_tags_json, RedFlag.raw_service_tags_json, RedFlag.service_tags_json)
        .filter(
            RedFlag.raw_product_tags_json.isnot(None) if norm_scope == "product" else RedFlag.raw_service_tags_json.isnot(None)
        )
        .all()
    )
    for row in rows:
        if norm_scope == "product":
            raw_tags = _parse_tags_json(row[0])
            normalized_tags = _parse_tags_json(row[1])
        else:
            raw_tags = _parse_tags_json(row[2])
            normalized_tags = _parse_tags_json(row[3])

        if not raw_tags or not normalized_tags:
            continue
        if fallback not in {t.strip().lower() for t in normalized_tags}:
            continue

        for idx, raw_value in enumerate(raw_tags):
            raw_clean = str(raw_value or "").strip()
            if not raw_clean:
                continue
            mapped_value = normalized_tags[idx] if idx < len(normalized_tags) else ""
            if str(mapped_value).strip().lower() != fallback:
                continue
            key = _norm_key(raw_clean)
            counts[key] = counts.get(key, 0) + 1
            if key not in examples:
                examples[key] = raw_clean

    ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    total = len(ordered)
    window = ordered[offset : offset + limit]
    data = [{"raw_value": examples.get(k, k.replace("_", " ")), "raw_value_key": k, "count": c} for k, c in window]
    return {
        "success": True,
        "scope": norm_scope,
        "fallback": fallback,
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": data,
    }


def _apply_synonym_to_existing_rows(db: Session, scope: str, raw_value_key: str, canonical_value: str) -> int:
    updated = 0
    now = datetime.now(timezone.utc)

    if scope == "category":
        rows = db.query(RedFlag).filter(RedFlag.raw_category.isnot(None)).all()
        for r in rows:
            if _norm_key(r.raw_category) == raw_value_key:
                if (r.category or "").strip().lower() != canonical_value:
                    r.category = canonical_value
                    updated += 1
        return updated

    rows = db.query(RedFlag).all()
    fallback = _SCOPE_FALLBACK[scope]
    for r in rows:
        if scope == "product":
            raw_tags = _parse_tags_json(r.raw_product_tags_json)
            norm_tags = _parse_tags_json(r.product_tags_json)
        else:
            raw_tags = _parse_tags_json(r.raw_service_tags_json)
            norm_tags = _parse_tags_json(r.service_tags_json)

        if not raw_tags or not norm_tags:
            continue

        changed = False
        for idx, raw in enumerate(raw_tags):
            if _norm_key(raw) != raw_value_key:
                continue
            if idx >= len(norm_tags):
                continue
            if str(norm_tags[idx]).strip().lower() != fallback:
                continue
            norm_tags[idx] = canonical_value
            changed = True

        if changed:
            deduped: list[str] = []
            seen: set[str] = set()
            for t in norm_tags:
                tv = str(t).strip().lower()
                if not tv or tv in seen:
                    continue
                seen.add(tv)
                deduped.append(tv)
            if scope == "product":
                r.product_tags_json = json.dumps(deduped, separators=(",", ":"))
            else:
                r.service_tags_json = json.dumps(deduped, separators=(",", ":"))
            updated += 1

    return updated


@app.post("/api/admin/red-flag-synonyms")
def upsert_red_flag_synonym(
    request: Request,
    payload: RedFlagSynonymUpsertRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    scope = payload.scope.strip().lower()
    if scope not in {"category", "product", "service"}:
        raise HTTPException(status_code=400, detail="scope must be one of: category, product, service")

    raw_value = payload.raw_value.strip()
    if not raw_value:
        raise HTTPException(status_code=400, detail="raw_value is required")
    raw_value_key = _norm_key(raw_value)
    canonical_value = _norm_key(payload.canonical_value)
    if not canonical_value:
        raise HTTPException(status_code=400, detail="canonical_value is required")

    now = datetime.now(timezone.utc)
    try:
        row = (
            db.query(RedFlagSynonym)
            .filter(
                RedFlagSynonym.scope == scope,
                RedFlagSynonym.raw_value_key == raw_value_key,
            )
            .first()
        )
        created = False
        if row is None:
            created = True
            row = RedFlagSynonym(
                scope=scope,
                raw_value=raw_value,
                raw_value_key=raw_value_key,
                canonical_value=canonical_value,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            db.add(row)
        else:
            row.raw_value = raw_value
            row.canonical_value = canonical_value
            row.is_active = True
            row.updated_at = now

        updated_rows = 0
        if payload.apply_existing:
            updated_rows = _apply_synonym_to_existing_rows(db, scope, raw_value_key, canonical_value)

        db.commit()
        db.refresh(row)
        _record_audit_event(
            db,
            module_code="red_flags_admin",
            action="synonym_upserted",
            entity_type="red_flag_synonym",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={
                "scope": row.scope,
                "raw_value": row.raw_value,
                "canonical_value": row.canonical_value,
                "updated_existing_rows": updated_rows,
                "created": created,
            },
        )
        db.commit()
        return {
            "success": True,
            "created": created,
            "updated_existing_rows": updated_rows,
            "data": {
                "id": row.id,
                "scope": row.scope,
                "raw_value": row.raw_value,
                "raw_value_key": row.raw_value_key,
                "canonical_value": row.canonical_value,
                "is_active": bool(row.is_active),
            },
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.patch("/api/admin/red-flag-synonyms/{synonym_id}")
def update_red_flag_synonym(
    request: Request,
    synonym_id: int,
    payload: RedFlagSynonymUpdateRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        row = db.query(RedFlagSynonym).filter(RedFlagSynonym.id == synonym_id).first()
        if row is None:
            raise HTTPException(status_code=404, detail="Synonym mapping not found.")

        scope = _norm_key(payload.scope) if payload.scope is not None else _norm_key(row.scope)
        if scope not in {"category", "product", "service"}:
            raise HTTPException(status_code=400, detail="scope must be one of: category, product, service")

        raw_value = payload.raw_value.strip() if payload.raw_value is not None else str(row.raw_value or "").strip()
        if not raw_value:
            raise HTTPException(status_code=400, detail="raw_value is required")
        raw_value_key = _norm_key(raw_value)

        canonical_input = payload.canonical_value if payload.canonical_value is not None else row.canonical_value
        canonical_value = _norm_key(canonical_input)
        if not canonical_value:
            raise HTTPException(status_code=400, detail="canonical_value is required")

        existing = (
            db.query(RedFlagSynonym.id)
            .filter(
                RedFlagSynonym.scope == scope,
                RedFlagSynonym.raw_value_key == raw_value_key,
                RedFlagSynonym.id != synonym_id,
            )
            .first()
        )
        if existing:
            raise HTTPException(status_code=409, detail="A synonym mapping with this scope/raw value already exists.")

        row.scope = scope
        row.raw_value = raw_value
        row.raw_value_key = raw_value_key
        row.canonical_value = canonical_value
        if payload.is_active is not None:
            row.is_active = bool(payload.is_active)
        row.updated_at = datetime.now(timezone.utc)

        updated_rows = 0
        if payload.apply_existing:
            updated_rows = _apply_synonym_to_existing_rows(db, scope, raw_value_key, canonical_value)

        db.commit()
        db.refresh(row)
        _record_audit_event(
            db,
            module_code="red_flags_admin",
            action="synonym_updated",
            entity_type="red_flag_synonym",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={
                "scope": row.scope,
                "raw_value": row.raw_value,
                "canonical_value": row.canonical_value,
                "is_active": bool(row.is_active),
                "updated_existing_rows": updated_rows,
            },
        )
        db.commit()
        return {
            "success": True,
            "updated_existing_rows": updated_rows,
            "data": {
                "id": row.id,
                "scope": row.scope,
                "raw_value": row.raw_value,
                "raw_value_key": row.raw_value_key,
                "canonical_value": row.canonical_value,
                "is_active": bool(row.is_active),
            },
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.delete("/api/admin/red-flag-synonyms/{synonym_id}")
def delete_red_flag_synonym(
    request: Request,
    synonym_id: int,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        row = db.query(RedFlagSynonym).filter(RedFlagSynonym.id == synonym_id).first()
        if row is None:
            raise HTTPException(status_code=404, detail="Synonym mapping not found.")
        _record_audit_event(
            db,
            module_code="red_flags_admin",
            action="synonym_deleted",
            entity_type="red_flag_synonym",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"scope": row.scope, "raw_value": row.raw_value, "canonical_value": row.canonical_value},
        )
        db.delete(row)
        db.commit()
        return {"success": True, "deleted": True, "id": synonym_id}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/operational-reporting/catalog")
def operational_reporting_catalog(
    request: Request,
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authenticated session required.")

    user_email = _session_user_email(request)
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email not found in session.")

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            raise HTTPException(status_code=403, detail=f"Unknown user: {user_email}")
        reports = _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)
        return {
            "is_platform_admin": is_platform_admin,
            "tenant_scope": "all" if is_platform_admin else tenant_ids,
            "reports": reports,
        }
    finally:
        db.close()


@app.get("/api/operational-reporting/users-by-role")
def operational_reporting_users_by_role(
    request: Request,
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authenticated session required.")

    user_email = _session_user_email(request)
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email not found in session.")

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            raise HTTPException(status_code=403, detail=f"Unknown user: {user_email}")
        authorized_codes = {str(item["code"]) for item in _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)}
        if "users_by_role" not in authorized_codes:
            raise HTTPException(status_code=403, detail="Not authorized for users_by_role.")
        tenant_scope = None if is_platform_admin else tenant_ids
        return _run_users_by_role_report(db, tenant_scope)
    finally:
        db.close()


@app.get("/api/operational-reporting/module-entitlements")
def operational_reporting_module_entitlements(
    request: Request,
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authenticated session required.")

    user_email = _session_user_email(request)
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email not found in session.")

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            raise HTTPException(status_code=403, detail=f"Unknown user: {user_email}")
        authorized_codes = {str(item["code"]) for item in _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)}
        if "module_entitlements" not in authorized_codes:
            raise HTTPException(status_code=403, detail="Not authorized for module_entitlements.")
        tenant_scope = None if is_platform_admin else tenant_ids
        return _run_module_entitlements_report(db, tenant_scope)
    finally:
        db.close()


@app.get("/api/operational-reporting/audit-events")
def operational_reporting_audit_events(
    request: Request,
    limit: int = Query(default=500, ge=1, le=2000),
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authenticated session required.")

    user_email = _session_user_email(request)
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email not found in session.")

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            raise HTTPException(status_code=403, detail=f"Unknown user: {user_email}")
        authorized_codes = {str(item["code"]) for item in _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)}
        if "audit_events" not in authorized_codes:
            raise HTTPException(status_code=403, detail="Not authorized for audit_events.")
        tenant_scope = None if is_platform_admin else tenant_ids
        return _run_audit_events_report(db, tenant_scope, limit=limit)
    finally:
        db.close()


@app.get("/api/operational-reporting/red-flag-workspace-capabilities")
def operational_reporting_red_flag_workspace_capabilities(
    request: Request,
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authenticated session required.")

    user_email = _session_user_email(request)
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email not found in session.")

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            raise HTTPException(status_code=403, detail=f"Unknown user: {user_email}")
        authorized_codes = {str(item["code"]) for item in _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)}
        if "red_flag_workspace_capabilities" not in authorized_codes:
            raise HTTPException(status_code=403, detail="Not authorized for red_flag_workspace_capabilities.")
        tenant_scope = None if is_platform_admin else tenant_ids
        return _run_red_flag_workspace_capabilities_by_role_report(db, tenant_scope)
    finally:
        db.close()


@app.get("/api/operational-reporting/export-csv")
def operational_reporting_export_csv(
    request: Request,
    report_code: str = Query(..., min_length=1),
):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authenticated session required.")

    user_email = _session_user_email(request)
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email not found in session.")

    db = get_db()
    try:
        user_id, is_platform_admin, tenant_ids = _get_user_scope(db, user_email)
        if not user_id:
            raise HTTPException(status_code=403, detail=f"Unknown user: {user_email}")

        authorized_reports = _operational_reports_for_user(db, user_id, is_platform_admin, tenant_ids)
        authorized_codes = {str(item["code"]) for item in authorized_reports}
        if report_code not in authorized_codes:
            raise HTTPException(status_code=403, detail=f"Not authorized for {report_code}.")

        tenant_scope = None if is_platform_admin else tenant_ids
        csv_text, base_name = _export_operational_report_csv(db, report_code, tenant_scope)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{base_name}_{timestamp}.csv"
        return Response(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    finally:
        db.close()


@app.get("/ui/entity-search")
def entity_search_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    db = get_db()
    try:
        is_platform_admin = _is_platform_admin_user(db, user_email)
        investigator_tenants = (
            _accessible_tenant_summaries_for_role(db, user_email or "", "tenant_investigator")
            if user_email
            else []
        )
        admin_tenants = (
            _accessible_tenant_summaries_for_role(db, user_email or "", "tenant_admin")
            if user_email
            else []
        )
        if is_platform_admin:
            accessible_tenants = _accessible_tenant_summaries_for_user(db, user_email or "", True)
        else:
            merged: dict[int, dict[str, object]] = {}
            for t in investigator_tenants + admin_tenants:
                merged[int(t["id"])] = t
            accessible_tenants = list(merged.values())

        if not accessible_tenants:
            raise HTTPException(
                status_code=403,
                detail="Entity Search requires tenant_investigator or tenant_admin role.",
            )
        default_tenant_id = int(accessible_tenants[0]["id"])
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="entity_search.html",
        context={
            "title": "Entity Search",
            "user": request.session["user"],
            "default_user_email": user_email or "",
            "default_tenant_id": default_tenant_id,
            "accessible_tenants": accessible_tenants,
            "csrf_token": get_csrf_token(request),
        },
    )


@app.get("/ui/exposure-search")
def exposure_search_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    user_email = _session_user_email(request)
    db = get_db()
    try:
        is_platform_admin = _is_platform_admin_user(db, user_email)
        investigator_tenants = (
            _accessible_tenant_summaries_for_role(db, user_email or "", "tenant_investigator")
            if user_email
            else []
        )
        admin_tenants = (
            _accessible_tenant_summaries_for_role(db, user_email or "", "tenant_admin")
            if user_email
            else []
        )
        if is_platform_admin:
            accessible_tenants = _accessible_tenant_summaries_for_user(db, user_email or "", True)
        else:
            merged: dict[int, dict[str, object]] = {}
            for t in investigator_tenants + admin_tenants:
                merged[int(t["id"])] = t
            accessible_tenants = list(merged.values())

        if not accessible_tenants:
            raise HTTPException(
                status_code=403,
                detail="Exposure Search requires tenant_investigator or tenant_admin role.",
            )
        default_tenant_id = int(accessible_tenants[0]["id"])
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="exposure_search.html",
        context={
            "title": "Exposure Search",
            "user": request.session["user"],
            "default_user_email": user_email or "",
            "default_tenant_id": default_tenant_id,
            "accessible_tenants": accessible_tenants,
            "csrf_token": get_csrf_token(request),
        },
    )


@app.get("/ui/red-flags/selections")
def red_flag_selections_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/ui/red-flags/workspace?view=selections", status_code=303)


@app.get("/ui/red-flags/approvals")
def red_flag_approvals_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/ui/red-flags/workspace?view=approvals&status=pending_approval", status_code=303)


@app.get("/ui/red-flags/audit")
def red_flag_audit_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/ui/red-flags/workspace?view=audit", status_code=303)


@app.get("/ui/admin/tenants")
def tenant_admin_ui(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    db = get_db()
    accessible_tenants: list[dict[str, object]] = []
    is_platform_admin = False
    try:
        session_email = _session_user_email(request) or ""
        is_platform_admin = _is_platform_admin_user(db, session_email)
        tenant_admin_tenants = _accessible_tenant_summaries_for_role(
            db,
            session_email,
            role_code="tenant_admin",
        )
        if not is_platform_admin and not tenant_admin_tenants:
            raise HTTPException(
                status_code=403,
                detail="Tenant Management UI requires platform admin or tenant_admin role.",
            )
        if is_platform_admin:
            accessible_tenants = _accessible_tenant_summaries_for_user(db, session_email, True)
        else:
            accessible_tenants = tenant_admin_tenants
    finally:
        db.close()

    return templates.TemplateResponse(
        request=request,
        name="tenant_admin.html",
        context={
            "title": "Tenant Management",
            "user": request.session["user"],
            "is_platform_admin": is_platform_admin,
            "accessible_tenants": accessible_tenants,
            "module_codes": list(SUPPORTED_MODULE_CODES),
            "csrf_token": get_csrf_token(request),
        },
    )


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    session_user_email = _session_user_email(request)
    db = get_db()
    try:
        actor_user_id = _get_user_id_by_email(db, session_user_email) if session_user_email else None
        _record_audit_event(
            db,
            module_code="auth",
            action="logout",
            actor_user_id=actor_user_id,
            actor_email=session_user_email,
            request=request,
            payload={"status": "success"},
        )
        db.commit()
    finally:
        db.close()
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


def has_users() -> bool:
    db = get_db()
    try:
        return db.query(AppUser.id).filter(AppUser.password_hash.isnot(None)).first() is not None
    finally:
        db.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/platform/auth/context")
def platform_auth_context(auth: AuthContext = Depends(require_authenticated_user)):
    return {"user_email": auth.user_email}


@app.get("/api/platform/tenant/context")
def platform_tenant_context(auth: AuthContext = Depends(require_tenant_context)):
    return {"user_email": auth.user_email, "tenant_id": auth.tenant_id}


@app.get("/api/platform/admin/context")
def platform_admin_context(auth: AuthContext = Depends(require_platform_admin)):
    return {"user_email": auth.user_email, "platform_admin": True}


def _serialize_workflow_payload(db: Session, version: WorkflowDefinitionVersion) -> dict:
    states = (
        db.query(WorkflowState)
        .filter(WorkflowState.workflow_version_id == version.id)
        .order_by(WorkflowState.is_initial.desc(), WorkflowState.state_code.asc())
        .all()
    )
    transitions = (
        db.query(WorkflowTransition)
        .filter(WorkflowTransition.workflow_version_id == version.id)
        .order_by(WorkflowTransition.transition_code.asc())
        .all()
    )
    transition_ids = [t.id for t in transitions]
    roles_by_transition: dict[int, list[str]] = {}
    if transition_ids:
        role_rows = (
            db.query(WorkflowTransitionRole)
            .filter(WorkflowTransitionRole.workflow_transition_id.in_(transition_ids))
            .all()
        )
        for row in role_rows:
            roles_by_transition.setdefault(row.workflow_transition_id, []).append(row.role_code)

    return {
        "states": [
            {
                "state_code": s.state_code,
                "display_name": s.display_name,
                "is_initial": s.is_initial,
                "is_terminal": s.is_terminal,
                "capabilities": _parse_string_list_json(s.capabilities_json),
            }
            for s in states
        ],
        "transitions": [
            {
                "transition_code": t.transition_code,
                "from_state_code": t.from_state_code,
                "to_state_code": t.to_state_code,
                "requires_comment": t.requires_comment,
                "allowed_roles": sorted(roles_by_transition.get(t.id, [])),
            }
            for t in transitions
        ],
    }


def _serialize_workflow_version(db: Session, definition: WorkflowDefinition, version: WorkflowDefinitionVersion) -> dict:
    payload = _serialize_workflow_payload(db, version)
    return {
        "workflow_definition_id": definition.id,
        "workflow_name": definition.name,
        "module_code": definition.module_code,
        "entity_type": definition.entity_type,
        "is_system_template": definition.is_system_template,
        "workflow_version_id": version.id,
        "version_no": version.version_no,
        "status": version.status,
        "is_active": version.is_active,
        "published_at": version.published_at.isoformat() if version.published_at else None,
        "states": payload.get("states", []),
        "transitions": payload.get("transitions", []),
    }


_RED_FLAGS_WORKFLOW_ENTITY_TYPE = "tenant_red_flag_selection"
_RED_FLAGS_FALLBACK_WORKFLOW_PAYLOAD = {
    "states": [
        {
            "state_code": "draft",
            "display_name": "Draft",
            "is_initial": True,
            "is_terminal": False,
            "capabilities": ["catalog_view", "in_flight_view", "selection_edit"],
        },
        {
            "state_code": "pending_approval",
            "display_name": "Pending Approval",
            "is_initial": False,
            "is_terminal": False,
            "capabilities": ["in_flight_view", "approval_review"],
        },
        {
            "state_code": "approved",
            "display_name": "Approved",
            "is_initial": False,
            "is_terminal": True,
            "capabilities": ["completed_view", "audit_view"],
        },
        {
            "state_code": "rejected",
            "display_name": "Rejected",
            "is_initial": False,
            "is_terminal": False,
            "capabilities": ["in_flight_view", "selection_edit"],
        },
        {
            "state_code": "returned",
            "display_name": "Returned",
            "is_initial": False,
            "is_terminal": False,
            "capabilities": ["in_flight_view", "selection_edit"],
        },
    ],
    "transitions": [
        {
            "transition_code": "submit_from_draft",
            "from_state_code": "draft",
            "to_state_code": "pending_approval",
            "requires_comment": False,
            "allowed_roles": ["tenant_admin", "red_flag_analyst"],
        },
        {
            "transition_code": "submit_from_returned",
            "from_state_code": "returned",
            "to_state_code": "pending_approval",
            "requires_comment": False,
            "allowed_roles": ["tenant_admin", "red_flag_analyst"],
        },
        {
            "transition_code": "submit_from_rejected",
            "from_state_code": "rejected",
            "to_state_code": "pending_approval",
            "requires_comment": False,
            "allowed_roles": ["tenant_admin", "red_flag_analyst"],
        },
        {
            "transition_code": "approve",
            "from_state_code": "pending_approval",
            "to_state_code": "approved",
            "requires_comment": False,
            "allowed_roles": ["tenant_admin", "red_flag_approver"],
        },
        {
            "transition_code": "reject",
            "from_state_code": "pending_approval",
            "to_state_code": "rejected",
            "requires_comment": False,
            "allowed_roles": ["tenant_admin", "red_flag_approver"],
        },
        {
            "transition_code": "return",
            "from_state_code": "pending_approval",
            "to_state_code": "returned",
            "requires_comment": False,
            "allowed_roles": ["tenant_admin", "red_flag_approver"],
        },
    ],
}


def _get_user_tenant_role_codes(db: Session, tenant_id: int, user_email: str | None) -> set[str]:
    email = (user_email or "").strip().lower()
    if not email:
        return set()
    rows = (
        db.query(Role.code)
        .join(TenantUserRole, TenantUserRole.role_id == Role.id)
        .join(TenantUser, TenantUser.id == TenantUserRole.tenant_user_id)
        .join(AppUser, AppUser.id == TenantUser.app_user_id)
        .filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.status == "active",
            func.lower(AppUser.email) == email,
        )
        .all()
    )
    return {str(r[0]).strip() for r in rows if str(r[0]).strip()}


def _get_active_workflow_payload(
    db: Session,
    tenant_id: int,
    module_code: str,
    entity_type: str,
) -> tuple[dict, str]:
    binding = (
        db.query(TenantWorkflowBinding)
        .filter(
            TenantWorkflowBinding.tenant_id == tenant_id,
            TenantWorkflowBinding.module_code == module_code,
            TenantWorkflowBinding.entity_type == entity_type,
        )
        .first()
    )
    if binding:
        row = (
            db.query(WorkflowDefinition, WorkflowDefinitionVersion)
            .join(
                WorkflowDefinitionVersion,
                WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
            )
            .filter(
                WorkflowDefinitionVersion.id == binding.workflow_version_id,
                WorkflowDefinitionVersion.is_active.is_(True),
                WorkflowDefinition.module_code == module_code,
                WorkflowDefinition.entity_type == entity_type,
            )
            .first()
        )
        if row:
            return _serialize_workflow_payload(db, row[1]), "binding"

    fallback = (
        db.query(WorkflowDefinition, WorkflowDefinitionVersion)
        .join(
            WorkflowDefinitionVersion,
            WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
        )
        .filter(
            WorkflowDefinition.module_code == module_code,
            WorkflowDefinition.entity_type == entity_type,
            WorkflowDefinition.is_system_template.is_(True),
            WorkflowDefinitionVersion.is_active.is_(True),
        )
        .first()
    )
    if fallback:
        return _serialize_workflow_payload(db, fallback[1]), "system_template"

    if module_code == "red_flags" and entity_type == _RED_FLAGS_WORKFLOW_ENTITY_TYPE:
        return _RED_FLAGS_FALLBACK_WORKFLOW_PAYLOAD, "fallback_legacy"

    return {"states": [], "transitions": []}, "none"


def _get_active_workflow_payload_safe(
    db: Session,
    tenant_id: int,
    module_code: str,
    entity_type: str,
) -> tuple[dict, str]:
    try:
        return _get_active_workflow_payload(db, tenant_id, module_code, entity_type)
    except Exception:
        # Keep workspace endpoints resilient even if workflow resolution code
        # encounters runtime issues.
        if module_code == "red_flags" and entity_type == _RED_FLAGS_WORKFLOW_ENTITY_TYPE:
            return _RED_FLAGS_FALLBACK_WORKFLOW_PAYLOAD, "fallback_runtime_error"
        return {"states": [], "transitions": []}, "none_runtime_error"


def _allowed_transitions_for_user(
    workflow_payload: dict,
    role_codes: set[str],
    *,
    from_state: str | None = None,
    to_state: str | None = None,
) -> list[dict]:
    out: list[dict] = []
    for transition in workflow_payload.get("transitions", []) or []:
        transition_from = str(transition.get("from_state_code", "")).strip()
        transition_to = str(transition.get("to_state_code", "")).strip()
        if from_state is not None and transition_from != from_state:
            continue
        if to_state is not None and transition_to != to_state:
            continue
        allowed_roles = {str(code).strip() for code in (transition.get("allowed_roles") or []) if str(code).strip()}
        if allowed_roles and role_codes.isdisjoint(allowed_roles):
            continue
        out.append(transition)
    return out


def _selection_action_from_to_state(to_state_code: str) -> tuple[str | None, str]:
    to_state = (to_state_code or "").strip()
    if to_state == "pending_approval":
        return "submit", "Submit"
    if to_state == "approved":
        return "approve", "Approve"
    if to_state == "rejected":
        return "reject", "Reject"
    if to_state == "returned":
        return "return", "Return"
    return None, to_state.replace("_", " ").title() if to_state else "Transition"


def _workflow_state_capability_map(states: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for state in states or []:
        code = str(state.get("state_code", "")).strip()
        if not code:
            continue
        caps: set[str] = set()
        for raw in (state.get("capabilities") or []):
            cap = str(raw).strip()
            if cap:
                caps.add(cap)
        out[code] = caps
    return out


def _workflow_state_roles_map(transitions: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for transition in transitions or []:
        from_code = str(transition.get("from_state_code", "")).strip()
        to_code = str(transition.get("to_state_code", "")).strip()
        allowed_roles = {
            str(role_code).strip()
            for role_code in (transition.get("allowed_roles") or [])
            if str(role_code).strip()
        }
        for code in (from_code, to_code):
            if not code:
                continue
            out.setdefault(code, set()).update(allowed_roles)
    return out


def _workflow_accessible_state_codes(
    states: list[dict],
    transitions: list[dict],
    role_codes: set[str],
) -> set[str]:
    state_roles = _workflow_state_roles_map(transitions)
    out: set[str] = set()
    for state in states or []:
        code = str(state.get("state_code", "")).strip()
        if not code:
            continue
        allowed_roles = state_roles.get(code, set())
        if not allowed_roles or bool(role_codes & allowed_roles):
            out.add(code)
    return out


def _workflow_user_capabilities(
    states: list[dict],
    transitions: list[dict],
    role_codes: set[str],
) -> set[str]:
    state_caps = _workflow_state_capability_map(states)
    accessible_states = _workflow_accessible_state_codes(states, transitions, role_codes)
    out: set[str] = set()
    for state_code in accessible_states:
        out.update(state_caps.get(state_code, set()))
    # Terminal-state viewing should remain available to authorized readers even
    # when they are not transition actors for those states.
    terminal_view_caps = {"completed_view", "audit_view"}
    for state in states or []:
        state_code = str(state.get("state_code", "")).strip()
        if not state_code or not bool(state.get("is_terminal")):
            continue
        out.update(state_caps.get(state_code, set()) & terminal_view_caps)
    return out


def _workflow_authorized_roles(module_code: str) -> tuple[str, ...]:
    if module_code == "red_flags":
        return ("tenant_admin", "red_flag_approver")
    if module_code == "transaction_monitoring":
        return ("tenant_admin", "tm_control_approver", "control_approver")
    return ("tenant_admin",)


def _validate_workflow_payload(payload: dict) -> WorkflowValidateResponse:
    states = payload.get("states") or []
    transitions = payload.get("transitions") or []

    errors: list[WorkflowValidateIssue] = []
    warnings: list[str] = []

    if not states:
        errors.append(WorkflowValidateIssue(code="NO_STATES", message="Workflow must include at least one state."))
        return WorkflowValidateResponse(valid=False, errors=errors, warnings=warnings)

    state_codes = []
    initial_count = 0
    terminal_count = 0
    for s in states:
        code = str(s.get("state_code", "")).strip()
        if not code:
            errors.append(WorkflowValidateIssue(code="INVALID_STATE", message="Each state must include state_code."))
            continue
        state_codes.append(code)
        if s.get("is_initial"):
            initial_count += 1
        if s.get("is_terminal"):
            terminal_count += 1

    if len(state_codes) != len(set(state_codes)):
        errors.append(WorkflowValidateIssue(code="DUPLICATE_STATE_CODE", message="state_code values must be unique."))
    if initial_count != 1:
        errors.append(
            WorkflowValidateIssue(
                code="INITIAL_STATE_COUNT_INVALID",
                message=f"Workflow must have exactly one initial state; found {initial_count}.",
            )
        )
    if terminal_count < 1:
        errors.append(WorkflowValidateIssue(code="NO_TERMINAL_STATE", message="Workflow must include at least one terminal state."))

    state_set = set(state_codes)
    outbound: dict[str, int] = {code: 0 for code in state_codes}
    approver_transition_present = False

    transition_codes: list[str] = []
    for t in transitions:
        transition_code = str(t.get("transition_code", "")).strip()
        if not transition_code:
            errors.append(WorkflowValidateIssue(code="INVALID_TRANSITION", message="Each transition must include transition_code."))
            continue
        transition_codes.append(transition_code)

        from_code = str(t.get("from_state_code", "")).strip()
        to_code = str(t.get("to_state_code", "")).strip()
        if from_code not in state_set or to_code not in state_set:
            errors.append(
                WorkflowValidateIssue(
                    code="UNKNOWN_STATE_REFERENCE",
                    message=f"Transition '{transition_code}' references unknown state(s): {from_code} -> {to_code}.",
                )
            )
            continue
        outbound[from_code] += 1

        allowed_roles = t.get("allowed_roles") or []
        if any(str(role).endswith("_approver") or str(role) == "application_admin" for role in allowed_roles):
            approver_transition_present = True

    if len(transition_codes) != len(set(transition_codes)):
        errors.append(
            WorkflowValidateIssue(code="DUPLICATE_TRANSITION_CODE", message="transition_code values must be unique.")
        )
    for s in states:
        code = str(s.get("state_code", "")).strip()
        if code and not s.get("is_terminal") and outbound.get(code, 0) == 0:
            errors.append(
                WorkflowValidateIssue(
                    code="NON_TERMINAL_WITHOUT_OUTBOUND",
                    message=f"State '{code}' has no outbound transitions.",
                )
            )
    if not approver_transition_present:
        errors.append(
            WorkflowValidateIssue(
                code="MISSING_APPROVER_TRANSITION",
                message="At least one transition must be assigned to an approver role.",
            )
        )
    if transitions and any(outbound.get(code, 0) == 1 for code in outbound):
        warnings.append("One or more non-terminal states have only a single outbound transition.")

    return WorkflowValidateResponse(valid=len(errors) == 0, errors=errors, warnings=warnings)


def _normalize_workflow_payload(states_in: list, transitions_in: list) -> dict:
    states = []
    for s in states_in:
        capabilities = []
        for raw in (s.capabilities or []):
            code = str(raw).strip()
            if not code or code in capabilities:
                continue
            capabilities.append(code)
        states.append(
            {
                "state_code": s.state_code.strip(),
                "display_name": s.display_name.strip(),
                "is_initial": bool(s.is_initial),
                "is_terminal": bool(s.is_terminal),
                "capabilities": capabilities,
            }
        )

    transitions = []
    for t in transitions_in:
        transitions.append(
            {
                "transition_code": t.transition_code.strip(),
                "from_state_code": t.from_state_code.strip(),
                "to_state_code": t.to_state_code.strip(),
                "requires_comment": bool(t.requires_comment),
                "allowed_roles": [str(role).strip() for role in (t.allowed_roles or []) if str(role).strip()],
            }
        )

    return {"states": states, "transitions": transitions}


def _resolve_actor_user_id(db: Session, auth: AuthContext) -> int:
    row = db.query(AppUser.id).filter(AppUser.email == auth.user_email).first()
    if not row:
        raise HTTPException(status_code=403, detail=f"Unknown user: {auth.user_email}")
    return int(row[0])


def _serialize_tenant(db: Session, tenant: Tenant) -> TenantOut:
    ent_rows = []
    table_inspector = inspect(engine)
    if table_inspector.has_table("ten_module_entitlements", schema=DB_SCHEMA):
        ent_rows = (
            db.query(TenantModuleEntitlement)
            .filter(TenantModuleEntitlement.tenant_id == tenant.id)
            .order_by(TenantModuleEntitlement.module_code.asc())
            .all()
        )
    entitlements = [
        TenantEntitlementOut(
            module_code=row.module_code,
            status=row.status,
            enabled_from=row.enabled_from.isoformat() if row.enabled_from else None,
            enabled_to=row.enabled_to.isoformat() if row.enabled_to else None,
        )
        for row in ent_rows
    ]
    return TenantOut(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        created_at=tenant.created_at.isoformat() if tenant.created_at else None,
        updated_at=tenant.updated_at.isoformat() if tenant.updated_at else None,
        entitlements=entitlements,
    )


def _serialize_business_unit(row: BusinessUnit) -> BusinessUnitOut:
    return BusinessUnitOut(
        id=int(row.id),
        tenant_id=int(row.tenant_id),
        code=row.code,
        name=row.name,
        status=row.status,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


_ALLOWED_DATA_HUB_AUTH_TYPES = {"none", "bearer_token", "api_key", "custom_header"}


def _normalize_data_hub_base_url(raw_url: str) -> str:
    value = str(raw_url or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="base_url is required.")
    if value.endswith("/"):
        value = value[:-1]
    if not (value.startswith("http://") or value.startswith("https://")):
        raise HTTPException(status_code=400, detail="base_url must start with http:// or https://")
    return value


def _serialize_tenant_data_hub_connection(row: TenantDataHubConnection) -> TenantDataHubConnectionOut:
    return TenantDataHubConnectionOut(
        tenant_id=int(row.tenant_id),
        base_url=row.base_url,
        auth_type=row.auth_type,
        auth_header_name=row.auth_header_name,
        auth_secret_ref=row.auth_secret_ref,
        connect_timeout_seconds=int(row.connect_timeout_seconds),
        read_timeout_seconds=int(row.read_timeout_seconds),
        is_active=bool(row.is_active),
        last_tested_at=row.last_tested_at.isoformat() if row.last_tested_at else None,
        last_test_status=row.last_test_status,
        last_test_message=row.last_test_message,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _validate_data_hub_connection_payload(payload: TenantDataHubConnectionUpsertRequest) -> dict[str, object]:
    auth_type = str(payload.auth_type or "").strip().lower()
    if auth_type not in _ALLOWED_DATA_HUB_AUTH_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"auth_type must be one of: {', '.join(sorted(_ALLOWED_DATA_HUB_AUTH_TYPES))}",
        )

    connect_timeout = int(payload.connect_timeout_seconds)
    read_timeout = int(payload.read_timeout_seconds)
    if connect_timeout < 1 or connect_timeout > 120:
        raise HTTPException(status_code=400, detail="connect_timeout_seconds must be between 1 and 120.")
    if read_timeout < 1 or read_timeout > 300:
        raise HTTPException(status_code=400, detail="read_timeout_seconds must be between 1 and 300.")

    auth_header_name = (payload.auth_header_name or "").strip() or None
    auth_secret_ref = (payload.auth_secret_ref or "").strip() or None
    if auth_type == "custom_header" and not auth_header_name:
        raise HTTPException(status_code=400, detail="auth_header_name is required when auth_type is custom_header.")

    return {
        "base_url": _normalize_data_hub_base_url(payload.base_url),
        "auth_type": auth_type,
        "auth_header_name": auth_header_name,
        "auth_secret_ref": auth_secret_ref,
        "connect_timeout_seconds": connect_timeout,
        "read_timeout_seconds": read_timeout,
        "is_active": bool(payload.is_active),
    }


def _data_hub_test_headers(row: TenantDataHubConnection) -> dict[str, str]:
    headers: dict[str, str] = {}
    secret_ref = str(row.auth_secret_ref or "").strip()
    if not secret_ref:
        return headers
    if row.auth_type == "bearer_token":
        headers["Authorization"] = f"Bearer {secret_ref}"
    elif row.auth_type == "api_key":
        headers["x-api-key"] = secret_ref
    elif row.auth_type == "custom_header" and row.auth_header_name:
        headers[row.auth_header_name] = secret_ref
    return headers


def _test_data_hub_connection(row: TenantDataHubConnection) -> tuple[str, str]:
    timeout = (int(row.connect_timeout_seconds), int(row.read_timeout_seconds))
    url = row.base_url.rstrip("/") + "/health"
    req = urllib.request.Request(url=url, method="GET", headers=_data_hub_test_headers(row))
    try:
        with urllib.request.urlopen(req, timeout=max(timeout)) as resp:
            body = resp.read(512).decode("utf-8", errors="replace")
            code = int(getattr(resp, "status", 200))
            if code >= 400:
                return "failed", f"Health check returned HTTP {code}"
            return "ok", f"Health check succeeded ({code}) {body[:120]}".strip()
    except urllib.error.HTTPError as exc:
        return "failed", f"Health check failed with HTTP {int(exc.code)}"
    except urllib.error.URLError as exc:
        return "failed", f"Health check connection error: {exc.reason}"
    except Exception as exc:
        return "failed", f"Health check error: {exc}"


def _resolve_tenant_data_hub_connection_or_404(db: Session, tenant_id: int) -> TenantDataHubConnection:
    row = (
        db.query(TenantDataHubConnection)
        .filter(
            TenantDataHubConnection.tenant_id == tenant_id,
            TenantDataHubConnection.is_active.is_(True),
        )
        .first()
    )
    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"No active Data Hub connection configured for tenant {tenant_id}.",
        )
    return row


def _proxy_data_hub_json(
    connection: TenantDataHubConnection,
    path: str,
    query_params: dict[str, object] | None = None,
) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in (query_params or {}).items() if v is not None}, doseq=True)
    url = connection.base_url.rstrip("/") + path
    if query:
        url = f"{url}?{query}"
    req = urllib.request.Request(
        url=url,
        method="GET",
        headers=_data_hub_test_headers(connection),
    )
    timeout = max(int(connection.connect_timeout_seconds), int(connection.read_timeout_seconds))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
        data = json.loads(payload) if payload else {}
        if not isinstance(data, dict):
            raise HTTPException(status_code=502, detail="Data Hub returned a non-object JSON response.")
        return data
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
        raise HTTPException(
            status_code=502,
            detail=f"Data Hub request failed ({int(exc.code)}): {body[:400]}",
        )
    except urllib.error.URLError as exc:
        raise HTTPException(status_code=502, detail=f"Data Hub connection error: {exc.reason}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Data Hub returned invalid JSON.")


def _accessible_tenants_for_user(db: Session, user_email: str, is_platform_admin: bool) -> list[Tenant]:
    if is_platform_admin:
        return db.query(Tenant).order_by(Tenant.name.asc()).all()

    user_row = db.query(AppUser.id).filter(func.lower(AppUser.email) == user_email.lower()).first()
    if not user_row:
        return []
    user_id = int(user_row[0])

    return (
        db.query(Tenant)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .filter(
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
        )
        .distinct()
        .order_by(Tenant.name.asc())
        .all()
    )


def _user_has_any_tenant_role(db: Session, user_email: str | None, tenant_id: int, role_codes: tuple[str, ...]) -> bool:
    if not user_email:
        return False
    user_id = _get_user_id_by_email(db, user_email)
    if not user_id:
        return False
    role_set = {str(r).strip() for r in role_codes if str(r).strip()}
    if not role_set:
        return False
    row = (
        db.query(TenantUserRole.id)
        .join(TenantUser, TenantUser.id == TenantUserRole.tenant_user_id)
        .join(Role, Role.id == TenantUserRole.role_id)
        .filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
            Role.code.in_(sorted(role_set)),
        )
        .first()
    )
    return row is not None


def _accessible_tenant_summaries_for_module_role(
    db: Session,
    user_email: str,
    module_code: str,
    role_code: str,
) -> list[dict[str, object]]:
    user_id = _get_user_id_by_email(db, user_email)
    if not user_id:
        return []

    rows = (
        db.query(Tenant.id, Tenant.name, Tenant.status)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .join(TenantUserRole, TenantUserRole.tenant_user_id == TenantUser.id)
        .join(Role, Role.id == TenantUserRole.role_id)
        .join(
            TenantModuleEntitlement,
            and_(
                TenantModuleEntitlement.tenant_id == Tenant.id,
                TenantModuleEntitlement.module_code == module_code,
                TenantModuleEntitlement.status == "active",
            ),
        )
        .filter(
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
            Role.code == role_code,
        )
        .distinct()
        .order_by(Tenant.name.asc())
        .all()
    )
    return [{"id": int(tid), "name": str(name), "status": str(status)} for tid, name, status in rows]


def _accessible_tenant_summaries_for_role(
    db: Session,
    user_email: str,
    role_code: str,
) -> list[dict[str, object]]:
    user_id = _get_user_id_by_email(db, user_email)
    if not user_id:
        return []

    rows = (
        db.query(Tenant.id, Tenant.name, Tenant.status)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .join(TenantUserRole, TenantUserRole.tenant_user_id == TenantUser.id)
        .join(Role, Role.id == TenantUserRole.role_id)
        .filter(
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
            Role.code == role_code,
        )
        .distinct()
        .order_by(Tenant.name.asc())
        .all()
    )
    return [{"id": int(tid), "name": str(name), "status": str(status)} for tid, name, status in rows]


def _accessible_tenant_summaries_for_user(
    db: Session, user_email: str, is_platform_admin: bool
) -> list[dict[str, object]]:
    if is_platform_admin:
        rows = db.query(Tenant).order_by(Tenant.name.asc()).all()
        return [{"id": int(t.id), "name": t.name, "status": t.status} for t in rows]

    user_row = db.query(AppUser.id).filter(func.lower(AppUser.email) == user_email.lower()).first()
    if not user_row:
        return []
    user_id = int(user_row[0])

    tenant_id_rows = (
        db.query(TenantUser.tenant_id)
        .filter(
            TenantUser.app_user_id == user_id,
            TenantUser.status == "active",
        )
        .distinct()
        .order_by(TenantUser.tenant_id.asc())
        .all()
    )
    tenant_ids = [int(r[0]) for r in tenant_id_rows]
    if not tenant_ids:
        return []

    tenant_rows = db.query(Tenant).filter(Tenant.id.in_(tenant_ids)).all()
    tenant_by_id = {int(t.id): t for t in tenant_rows}

    summaries: list[dict[str, object]] = []
    for tenant_id in tenant_ids:
        tenant = tenant_by_id.get(tenant_id)
        if tenant:
            summaries.append({"id": int(tenant.id), "name": tenant.name, "status": tenant.status})
        else:
            summaries.append({"id": int(tenant_id), "name": f"Tenant {tenant_id}", "status": "active"})
    return summaries


def _get_selection_or_404(db: Session, selection_id: int, tenant_id: int) -> TenantRedFlagSelection:
    selection = (
        db.query(TenantRedFlagSelection)
        .filter(
            TenantRedFlagSelection.id == selection_id,
            TenantRedFlagSelection.tenant_id == tenant_id,
        )
        .first()
    )
    if not selection:
        raise HTTPException(status_code=404, detail="Red flag selection not found.")
    return selection


def _missing_platform_admin_tables() -> list[str]:
    required_tables = ("ten_tenants", "ten_module_entitlements")
    table_inspector = inspect(engine)
    return [table for table in required_tables if not table_inspector.has_table(table, schema=DB_SCHEMA)]


def _to_selection_out(db: Session, selection: TenantRedFlagSelection) -> RedFlagSelectionOut:
    bu = db.query(BusinessUnit).filter(BusinessUnit.id == selection.business_unit_id).first()
    rf = None
    trf = None
    if selection.shared_red_flag_id is not None:
        rf = db.query(RedFlag).filter(RedFlag.id == selection.shared_red_flag_id).first()
    if selection.tenant_red_flag_id is not None:
        trf = (
            db.query(TenantRedFlag)
            .filter(
                TenantRedFlag.id == selection.tenant_red_flag_id,
                TenantRedFlag.tenant_id == selection.tenant_id,
            )
            .first()
        )

    category = rf.category if rf else (trf.category if trf else None)
    severity = rf.severity if rf else (trf.severity if trf else None)
    red_flag_text = rf.text if rf else (trf.text if trf else None)
    product_tags = _parse_tags_json(rf.product_tags_json) if rf else (_parse_tags_json(trf.product_tags_json) if trf else [])
    service_tags = _parse_tags_json(rf.service_tags_json) if rf else (_parse_tags_json(trf.service_tags_json) if trf else [])

    created_at = selection.created_at.isoformat() if selection.created_at else ""
    updated_at = selection.updated_at.isoformat() if selection.updated_at else ""

    return RedFlagSelectionOut(
        id=selection.id,
        tenant_id=selection.tenant_id,
        business_unit_id=selection.business_unit_id,
        business_unit_code=bu.code if bu else None,
        business_unit_name=bu.name if bu else None,
        shared_red_flag_id=selection.shared_red_flag_id,
        tenant_red_flag_id=selection.tenant_red_flag_id,
        category=category,
        severity=severity,
        red_flag_text=red_flag_text,
        product_tags=product_tags,
        service_tags=service_tags,
        relevance_status=selection.relevance_status,
        approval_status=selection.approval_status,
        rationale=selection.rationale,
        analyst_user_id=selection.analyst_user_id,
        approver_user_id=selection.approver_user_id,
        submitted_at=selection.submitted_at.isoformat() if selection.submitted_at else None,
        approved_at=selection.approved_at.isoformat() if selection.approved_at else None,
        created_at=created_at,
        updated_at=updated_at,
    )


def _record_selection_event(
    db: Session,
    selection: TenantRedFlagSelection,
    actor_user_id: int,
    event_type: str,
    from_state: str | None,
    to_state: str | None,
    payload: dict | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    db.add(
        WorkflowEvent(
            tenant_id=selection.tenant_id,
            module_code="red_flags",
            entity_type="tenant_red_flag_selection",
            entity_id=selection.id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            actor_user_id=actor_user_id,
            event_payload_json=json.dumps(payload or {}),
            created_at=now,
        )
    )


def _safe_json_dumps(value: dict | list | str | int | float | bool | None) -> str:
    try:
        return json.dumps(value)
    except Exception:
        return json.dumps({"raw": str(value)})


def _record_audit_event(
    db: Session,
    *,
    module_code: str,
    action: str,
    tenant_id: int | None = None,
    entity_type: str | None = None,
    entity_id: int | None = None,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    request: Request | None = None,
    payload: dict | list | str | int | float | bool | None = None,
) -> None:
    try:
        request_ip = None
        user_agent = None
        request_method = None
        request_path = None
        if request is not None:
            request_ip = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")
            request_method = request.method
            request_path = request.url.path

        db.add(
            AuditEvent(
                tenant_id=tenant_id,
                module_code=module_code,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                actor_user_id=actor_user_id,
                actor_email=(actor_email or "").strip().lower() or None,
                request_method=request_method,
                request_path=request_path,
                request_ip=request_ip,
                user_agent=user_agent,
                event_payload_json=_safe_json_dumps(payload),
                created_at=datetime.now(timezone.utc),
            )
        )
    except Exception:
        # Best effort: auditing should not block primary business actions.
        return


def _replace_workflow_graph(db: Session, version_id: int, payload: dict) -> None:
    existing_transition_ids = [
        row[0]
        for row in db.query(WorkflowTransition.id)
        .filter(WorkflowTransition.workflow_version_id == version_id)
        .all()
    ]
    if existing_transition_ids:
        db.query(WorkflowTransitionRole).filter(
            WorkflowTransitionRole.workflow_transition_id.in_(existing_transition_ids)
        ).delete(synchronize_session=False)

    db.query(WorkflowTransition).filter(
        WorkflowTransition.workflow_version_id == version_id
    ).delete(synchronize_session=False)
    db.query(WorkflowState).filter(
        WorkflowState.workflow_version_id == version_id
    ).delete(synchronize_session=False)

    for s in payload.get("states", []):
        db.add(
            WorkflowState(
                workflow_version_id=version_id,
                state_code=s["state_code"],
                display_name=s["display_name"],
                is_initial=bool(s.get("is_initial")),
                is_terminal=bool(s.get("is_terminal")),
                capabilities_json=json.dumps(s.get("capabilities") or []),
            )
        )
    db.flush()

    for t in payload.get("transitions", []):
        transition = WorkflowTransition(
            workflow_version_id=version_id,
            transition_code=t["transition_code"],
            from_state_code=t["from_state_code"],
            to_state_code=t["to_state_code"],
            requires_comment=bool(t.get("requires_comment")),
        )
        db.add(transition)
        db.flush()
        for role_code in t.get("allowed_roles", []):
            db.add(
                WorkflowTransitionRole(
                    workflow_transition_id=transition.id,
                    role_code=role_code,
                )
            )


@app.get("/api/platform/admin/workflow-templates", response_model=list[WorkflowVersionOut])
def list_platform_workflow_templates(
    _: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        rows = (
            db.query(WorkflowDefinition, WorkflowDefinitionVersion)
            .join(
                WorkflowDefinitionVersion,
                WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
            )
            .filter(
                WorkflowDefinition.is_system_template.is_(True),
                WorkflowDefinitionVersion.is_active.is_(True),
            )
            .all()
        )
        return [_serialize_workflow_version(db, defn, version) for defn, version in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/platform/workflows/{module_code}/{entity_type}", response_model=WorkflowVersionOut)
def get_tenant_workflow(
    module_code: str,
    entity_type: str,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    try:
        binding = (
            db.query(TenantWorkflowBinding)
            .filter(
                TenantWorkflowBinding.tenant_id == auth.tenant_id,
                TenantWorkflowBinding.module_code == module_code,
                TenantWorkflowBinding.entity_type == entity_type,
            )
            .first()
        )
        if not binding:
            fallback = (
                db.query(WorkflowDefinition, WorkflowDefinitionVersion)
                .join(
                    WorkflowDefinitionVersion,
                    WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
                )
                .filter(
                    WorkflowDefinition.module_code == module_code,
                    WorkflowDefinition.entity_type == entity_type,
                    WorkflowDefinition.is_system_template.is_(True),
                    WorkflowDefinitionVersion.is_active.is_(True),
                )
                .first()
            )
            if fallback:
                return _serialize_workflow_version(db, fallback[0], fallback[1])

            # If no persisted workflow exists yet, return module fallback payload when available.
            fallback_payload, fallback_source = _get_active_workflow_payload(
                db,
                auth.tenant_id,
                module_code=module_code,
                entity_type=entity_type,
            )
            if fallback_source == "fallback_legacy":
                return WorkflowVersionOut(
                    workflow_definition_id=0,
                    workflow_name=f"{module_code} {entity_type} fallback workflow",
                    module_code=module_code,
                    entity_type=entity_type,
                    is_system_template=True,
                    workflow_version_id=0,
                    version_no=0,
                    status="active",
                    is_active=True,
                    published_at=None,
                    states=[WorkflowStateOut(**s) for s in (fallback_payload.get("states") or [])],
                    transitions=[WorkflowTransitionOut(**t) for t in (fallback_payload.get("transitions") or [])],
                )
            raise HTTPException(status_code=404, detail="No workflow binding or system template found.")

        row = (
            db.query(WorkflowDefinition, WorkflowDefinitionVersion)
            .join(
                WorkflowDefinitionVersion,
                WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
            )
            .filter(
                WorkflowDefinitionVersion.id == binding.workflow_version_id,
                WorkflowDefinitionVersion.is_active.is_(True),
            )
            .first()
        )
        if not row:
            raise HTTPException(status_code=404, detail="Bound workflow version not found or inactive.")
        return _serialize_workflow_version(db, row[0], row[1])
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/platform/workflow-versions/{workflow_version_id}", response_model=WorkflowVersionOut)
def get_tenant_workflow_version(
    workflow_version_id: int,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    try:
        row = (
            db.query(WorkflowDefinition, WorkflowDefinitionVersion)
            .join(
                WorkflowDefinitionVersion,
                WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
            )
            .filter(WorkflowDefinitionVersion.id == workflow_version_id)
            .first()
        )
        if not row:
            raise HTTPException(status_code=404, detail="Workflow version not found.")
        definition, version = row
        if definition.is_system_template:
            # System templates are readable to tenant-scoped callers.
            return _serialize_workflow_version(db, definition, version)
        if definition.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=403, detail="Not authorized to read this workflow version.")
        _ = require_tenant_permission(definition.module_code, *_workflow_authorized_roles(definition.module_code))(auth, db)
        return _serialize_workflow_version(db, definition, version)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/platform/workflows/{module_code}/{entity_type}/draft", response_model=WorkflowDraftCreateResponse)
def create_tenant_workflow_draft(
    request: Request,
    module_code: str,
    entity_type: str,
    payload: WorkflowDraftCreateRequest,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    _ = require_tenant_permission(module_code, *_workflow_authorized_roles(module_code))(auth, db)
    try:
        source_version: WorkflowDefinitionVersion | None = None
        source_definition: WorkflowDefinition | None = None

        clone_from = payload.clone_from
        if clone_from and clone_from.workflow_version_id is not None:
            source_version = (
                db.query(WorkflowDefinitionVersion)
                .filter(WorkflowDefinitionVersion.id == clone_from.workflow_version_id)
                .first()
            )
            if not source_version:
                raise HTTPException(status_code=404, detail="Source workflow version not found.")
            source_definition = (
                db.query(WorkflowDefinition)
                .filter(WorkflowDefinition.id == source_version.workflow_definition_id)
                .first()
            )
        elif clone_from and clone_from.workflow_definition_id is not None:
            source_definition = (
                db.query(WorkflowDefinition)
                .filter(WorkflowDefinition.id == clone_from.workflow_definition_id)
                .first()
            )
            if not source_definition:
                raise HTTPException(status_code=404, detail="Source workflow definition not found.")
            source_version = (
                db.query(WorkflowDefinitionVersion)
                .filter(
                    WorkflowDefinitionVersion.workflow_definition_id == source_definition.id,
                    WorkflowDefinitionVersion.is_active.is_(True),
                )
                .order_by(WorkflowDefinitionVersion.version_no.desc())
                .first()
            )
        else:
            source_pair = (
                db.query(WorkflowDefinition, WorkflowDefinitionVersion)
                .join(
                    WorkflowDefinitionVersion,
                    WorkflowDefinitionVersion.workflow_definition_id == WorkflowDefinition.id,
                )
                .filter(
                    WorkflowDefinition.module_code == module_code,
                    WorkflowDefinition.entity_type == entity_type,
                    WorkflowDefinition.is_system_template.is_(True),
                    WorkflowDefinitionVersion.is_active.is_(True),
                )
                .first()
            )
            if source_pair:
                source_definition, source_version = source_pair

        if not source_definition or not source_version:
            raise HTTPException(status_code=404, detail="No source workflow found to clone.")
        if source_definition.module_code != module_code or source_definition.entity_type != entity_type:
            raise HTTPException(status_code=400, detail="Source workflow does not match module/entity.")
        source_payload = _serialize_workflow_payload(db, source_version)

        definition = WorkflowDefinition(
            module_code=module_code,
            entity_type=entity_type,
            tenant_id=auth.tenant_id,
            name=payload.name or f"Tenant {auth.tenant_id} {module_code} {entity_type} Draft",
            is_system_template=False,
            created_at=datetime.now(timezone.utc),
        )
        db.add(definition)
        db.flush()

        version = WorkflowDefinitionVersion(
            workflow_definition_id=definition.id,
            version_no=1,
            status="draft",
            is_active=False,
            published_at=None,
        )
        db.add(version)
        db.flush()
        _replace_workflow_graph(db, version.id, source_payload)
        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        _record_audit_event(
            db,
            module_code=module_code,
            action="workflow_draft_created",
            tenant_id=auth.tenant_id,
            entity_type=entity_type,
            entity_id=int(version.id),
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"workflow_definition_id": int(definition.id), "workflow_version_id": int(version.id)},
        )
        db.commit()

        return WorkflowDraftCreateResponse(
            success=True,
            workflow_definition_id=definition.id,
            workflow_version_id=version.id,
            status=version.status,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/platform/workflows/{module_code}/{entity_type}/draft/validate", response_model=WorkflowValidateResponse)
def validate_tenant_workflow_draft(
    module_code: str,
    entity_type: str,
    payload: WorkflowValidateRequest,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    _ = require_tenant_permission(module_code, *_workflow_authorized_roles(module_code))(auth, db)
    try:
        version = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.id == payload.version_id)
            .first()
        )
        if not version:
            raise HTTPException(status_code=404, detail="Workflow version not found.")

        definition = (
            db.query(WorkflowDefinition)
            .filter(WorkflowDefinition.id == version.workflow_definition_id)
            .first()
        )
        if not definition:
            raise HTTPException(status_code=404, detail="Workflow definition not found.")
        if definition.module_code != module_code or definition.entity_type != entity_type:
            raise HTTPException(status_code=400, detail="Workflow version does not match module/entity.")
        if definition.is_system_template or definition.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=403, detail="Not authorized to validate this workflow draft.")
        if version.status != "draft":
            raise HTTPException(status_code=400, detail="Only draft workflow versions can be validated.")

        draft_payload = _serialize_workflow_payload(db, version)
        return _validate_workflow_payload(draft_payload)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/platform/workflows/{module_code}/{entity_type}/draft/publish", response_model=WorkflowPublishResponse)
def publish_tenant_workflow_draft(
    request: Request,
    module_code: str,
    entity_type: str,
    payload: WorkflowPublishRequest,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    _ = require_tenant_permission(module_code, *_workflow_authorized_roles(module_code))(auth, db)
    try:
        version = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.id == payload.version_id)
            .first()
        )
        if not version:
            raise HTTPException(status_code=404, detail="Workflow version not found.")

        definition = (
            db.query(WorkflowDefinition)
            .filter(WorkflowDefinition.id == version.workflow_definition_id)
            .first()
        )
        if not definition:
            raise HTTPException(status_code=404, detail="Workflow definition not found.")
        if definition.module_code != module_code or definition.entity_type != entity_type:
            raise HTTPException(status_code=400, detail="Workflow version does not match module/entity.")
        if definition.is_system_template or definition.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=403, detail="Not authorized to publish this workflow draft.")
        if version.status != "draft":
            raise HTTPException(status_code=400, detail="Only draft workflow versions can be published.")

        validation = _validate_workflow_payload(_serialize_workflow_payload(db, version))
        if not validation.valid:
            raise HTTPException(status_code=400, detail={"message": "Draft validation failed.", "errors": [e.model_dump() for e in validation.errors]})

        db.query(WorkflowDefinitionVersion).filter(
            WorkflowDefinitionVersion.workflow_definition_id == definition.id,
            WorkflowDefinitionVersion.id != version.id,
            WorkflowDefinitionVersion.is_active.is_(True),
        ).update({"is_active": False}, synchronize_session=False)

        version.status = "published"
        version.is_active = True
        version.published_at = datetime.now(timezone.utc)

        binding = (
            db.query(TenantWorkflowBinding)
            .filter(
                TenantWorkflowBinding.tenant_id == auth.tenant_id,
                TenantWorkflowBinding.module_code == module_code,
                TenantWorkflowBinding.entity_type == entity_type,
            )
            .first()
        )
        if binding is None:
            binding = TenantWorkflowBinding(
                tenant_id=auth.tenant_id,
                module_code=module_code,
                entity_type=entity_type,
                workflow_version_id=version.id,
            )
            db.add(binding)
        else:
            binding.workflow_version_id = version.id

        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        _record_audit_event(
            db,
            module_code=module_code,
            action="workflow_published",
            tenant_id=auth.tenant_id,
            entity_type=entity_type,
            entity_id=int(version.id),
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"workflow_definition_id": int(definition.id), "publish_comment": payload.publish_comment},
        )
        db.commit()
        db.refresh(binding)

        return WorkflowPublishResponse(
            success=True,
            workflow_definition_id=definition.id,
            workflow_version_id=version.id,
            status=version.status,
            binding={
                "binding_id": binding.id,
                "tenant_id": binding.tenant_id,
                "module_code": binding.module_code,
                "entity_type": binding.entity_type,
                "workflow_version_id": binding.workflow_version_id,
                "publish_comment": payload.publish_comment,
            },
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.patch("/api/platform/workflows/{module_code}/{entity_type}/draft", response_model=WorkflowDraftUpdateResponse)
def update_tenant_workflow_draft(
    request: Request,
    module_code: str,
    entity_type: str,
    payload: WorkflowDraftUpdateRequest,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    _ = require_tenant_permission(module_code, *_workflow_authorized_roles(module_code))(auth, db)
    try:
        version = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.id == payload.version_id)
            .first()
        )
        if not version:
            raise HTTPException(status_code=404, detail="Workflow version not found.")

        definition = (
            db.query(WorkflowDefinition)
            .filter(WorkflowDefinition.id == version.workflow_definition_id)
            .first()
        )
        if not definition:
            raise HTTPException(status_code=404, detail="Workflow definition not found.")
        if definition.module_code != module_code or definition.entity_type != entity_type:
            raise HTTPException(status_code=400, detail="Workflow version does not match module/entity.")
        if definition.is_system_template or definition.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=403, detail="Not authorized to update this workflow draft.")
        if version.status != "draft":
            raise HTTPException(status_code=400, detail="Only draft workflow versions can be updated.")
        if not payload.states:
            raise HTTPException(status_code=400, detail="At least one state is required.")
        if not payload.transitions:
            raise HTTPException(status_code=400, detail="At least one transition is required.")

        normalized = _normalize_workflow_payload(payload.states, payload.transitions)
        validation = _validate_workflow_payload(normalized)
        if not validation.valid:
            raise HTTPException(
                status_code=400,
                detail={"message": "Draft update validation failed.", "errors": [e.model_dump() for e in validation.errors]},
            )

        _replace_workflow_graph(db, version.id, normalized)
        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        _record_audit_event(
            db,
            module_code=module_code,
            action="workflow_draft_updated",
            tenant_id=auth.tenant_id,
            entity_type=entity_type,
            entity_id=int(version.id),
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"workflow_definition_id": int(definition.id)},
        )
        db.commit()
        return WorkflowDraftUpdateResponse(
            success=True,
            workflow_version_id=version.id,
            status=version.status,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/platform/workflows/{module_code}/{entity_type}/draft/rollback", response_model=WorkflowRollbackResponse)
def rollback_tenant_workflow_binding(
    request: Request,
    module_code: str,
    entity_type: str,
    payload: WorkflowRollbackRequest,
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    _ = require_tenant_permission(module_code, *_workflow_authorized_roles(module_code))(auth, db)
    try:
        target_version = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.id == payload.target_workflow_version_id)
            .first()
        )
        if not target_version:
            raise HTTPException(status_code=404, detail="Target workflow version not found.")

        target_definition = (
            db.query(WorkflowDefinition)
            .filter(WorkflowDefinition.id == target_version.workflow_definition_id)
            .first()
        )
        if not target_definition:
            raise HTTPException(status_code=404, detail="Target workflow definition not found.")
        if target_definition.module_code != module_code or target_definition.entity_type != entity_type:
            raise HTTPException(status_code=400, detail="Target workflow does not match module/entity.")
        if (not target_definition.is_system_template) and target_definition.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=403, detail="Not authorized to rollback to this workflow.")

        binding = (
            db.query(TenantWorkflowBinding)
            .filter(
                TenantWorkflowBinding.tenant_id == auth.tenant_id,
                TenantWorkflowBinding.module_code == module_code,
                TenantWorkflowBinding.entity_type == entity_type,
            )
            .first()
        )

        previous_version_id = binding.workflow_version_id if binding else None
        if binding is None:
            binding = TenantWorkflowBinding(
                tenant_id=auth.tenant_id,
                module_code=module_code,
                entity_type=entity_type,
                workflow_version_id=target_version.id,
            )
            db.add(binding)
        else:
            binding.workflow_version_id = target_version.id

        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        _record_audit_event(
            db,
            module_code=module_code,
            action="workflow_rolled_back",
            tenant_id=auth.tenant_id,
            entity_type=entity_type,
            entity_id=int(target_version.id),
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"rolled_back_from_workflow_version_id": previous_version_id, "reason": payload.reason},
        )
        db.commit()
        return WorkflowRollbackResponse(
            success=True,
            active_workflow_version_id=target_version.id,
            rolled_back_from_workflow_version_id=previous_version_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/admin/tenants", response_model=list[TenantOut])
def list_admin_tenants(
    _: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    missing_tables = _missing_platform_admin_tables()
    if missing_tables:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Platform schema is not ready for tenant management.",
                "missing_tables": missing_tables,
                "hint": "Run ./scripts/migrate_db.sh local repair (or remote repair).",
            },
        )
    try:
        rows = db.query(Tenant).order_by(Tenant.name.asc()).all()
        return [_serialize_tenant(db, t) for t in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/admin/tenants", response_model=TenantOut)
def create_admin_tenant(
    request: Request,
    payload: TenantCreateRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    missing_tables = _missing_platform_admin_tables()
    if missing_tables:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Platform schema is not ready for tenant management.",
                "missing_tables": missing_tables,
                "hint": "Run ./scripts/migrate_db.sh local repair (or remote repair).",
            },
        )
    now = datetime.now(timezone.utc)
    normalized_name = " ".join(payload.name.split())
    if not normalized_name:
        raise HTTPException(status_code=400, detail="Tenant name is required.")
    if payload.status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="Tenant status must be active|inactive.")
    try:
        exists = (
            db.query(Tenant.id)
            .filter(func.lower(func.trim(Tenant.name)) == normalized_name.lower())
            .first()
        )
        if exists:
            raise HTTPException(status_code=409, detail="Tenant name already exists.")
        tenant = Tenant(name=normalized_name, status=payload.status, created_at=now, updated_at=now)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_created",
            entity_type="tenant",
            entity_id=int(tenant.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"name": tenant.name, "status": tenant.status},
        )
        db.commit()
        return _serialize_tenant(db, tenant)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/admin/tenants/{tenant_id}/entitlements", response_model=TenantOut)
def upsert_admin_tenant_entitlement(
    request: Request,
    tenant_id: int,
    payload: TenantEntitlementUpsertRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    if payload.status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="Entitlement status must be active|inactive.")
    module_code = payload.module_code.strip()
    if not module_code:
        raise HTTPException(status_code=400, detail="module_code is required.")
    if module_code not in SUPPORTED_MODULE_CODES:
        raise HTTPException(status_code=400, detail=f"Unsupported module_code. Allowed: {', '.join(SUPPORTED_MODULE_CODES)}")

    try:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found.")

        row = (
            db.query(TenantModuleEntitlement)
            .filter(
                TenantModuleEntitlement.tenant_id == tenant_id,
                TenantModuleEntitlement.module_code == module_code,
            )
            .first()
        )
        if row is None:
            row = TenantModuleEntitlement(
                tenant_id=tenant_id,
                module_code=module_code,
                status=payload.status,
                enabled_from=now if payload.status == "active" else None,
                enabled_to=None if payload.status == "active" else now,
                created_at=now,
            )
            db.add(row)
        else:
            row.status = payload.status
            if payload.status == "active":
                if row.enabled_from is None:
                    row.enabled_from = now
                row.enabled_to = None
            else:
                row.enabled_to = now

        tenant.updated_at = now
        db.commit()
        db.refresh(tenant)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_entitlement_upserted",
            tenant_id=int(tenant.id),
            entity_type="tenant",
            entity_id=int(tenant.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"module_code": module_code, "status": payload.status},
        )
        db.commit()
        return _serialize_tenant(db, tenant)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.patch("/api/admin/tenants/{tenant_id}/status", response_model=TenantOut)
def update_admin_tenant_status(
    request: Request,
    tenant_id: int,
    payload: TenantStatusUpdateRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    if payload.status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="Tenant status must be active|inactive.")
    now = datetime.now(timezone.utc)
    try:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found.")
        tenant.status = payload.status
        tenant.updated_at = now
        db.commit()
        db.refresh(tenant)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_status_updated",
            tenant_id=int(tenant.id),
            entity_type="tenant",
            entity_id=int(tenant.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"status": tenant.status},
        )
        db.commit()
        return _serialize_tenant(db, tenant)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.delete("/api/admin/tenants/{tenant_id}", response_model=TenantDeleteResponse)
def delete_admin_tenant(
    request: Request,
    tenant_id: int,
    confirm_name: str,
    force: bool = False,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    inspector = inspect(engine)
    try:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found.")
        if confirm_name.strip() != tenant.name:
            raise HTTPException(status_code=400, detail="confirm_name must exactly match tenant name.")

        linked_counts: dict[str, int] = {}
        table_checks = [
            ("tenant_users", "ten_users"),
            ("business_units", "ten_business_units"),
            ("tenant_module_entitlements", "ten_module_entitlements"),
            ("wf_tenant_bindings", "wf_tenant_bindings"),
            ("trf_selections", "trf_selections"),
        ]
        for label, table_name in table_checks:
            if inspector.has_table(table_name):
                count = db.execute(__import__("sqlalchemy").text(f"select count(*) from {table_name} where tenant_id = :tid"), {"tid": tenant_id}).scalar() or 0
                linked_counts[label] = int(count)
            else:
                linked_counts[label] = 0

        total_linked = sum(linked_counts.values())
        if total_linked > 0 and not force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "Tenant has linked data. Re-run with force=true to hard delete.",
                    "linked_counts": linked_counts,
                },
            )

        if force:
            # Delete dependent rows first if tables exist.
            for table_name in ["trf_selections", "wf_tenant_bindings", "ten_module_entitlements", "ten_business_units", "ten_users"]:
                if inspector.has_table(table_name):
                    db.execute(__import__("sqlalchemy").text(f"delete from {table_name} where tenant_id = :tid"), {"tid": tenant_id})

        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_deleted",
            tenant_id=int(tenant.id),
            entity_type="tenant",
            entity_id=int(tenant.id),
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"force": force, "linked_counts": linked_counts},
        )
        db.delete(tenant)
        db.commit()
        return TenantDeleteResponse(
            success=True,
            tenant_id=tenant_id,
            deleted=True,
            forced=force,
            details={"linked_counts": linked_counts},
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/red-flags/selections", response_model=RedFlagSelectionListResponse)
def list_red_flag_selections(
    business_unit_id: int | None = None,
    approval_status: str | None = None,
    relevance_status: str | None = None,
    include_deleted: bool = False,
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    try:
        q = db.query(TenantRedFlagSelection).filter(TenantRedFlagSelection.tenant_id == auth.tenant_id)
        if not include_deleted:
            q = q.filter(TenantRedFlagSelection.is_deleted.is_(False))
        if business_unit_id is not None:
            q = q.filter(TenantRedFlagSelection.business_unit_id == business_unit_id)
        if approval_status:
            q = q.filter(TenantRedFlagSelection.approval_status == approval_status)
        if relevance_status:
            q = q.filter(TenantRedFlagSelection.relevance_status == relevance_status)
        rows = q.order_by(TenantRedFlagSelection.updated_at.desc(), TenantRedFlagSelection.id.desc()).all()
        data = [_to_selection_out(db, row) for row in rows]
        return RedFlagSelectionListResponse(success=True, total=len(data), data=data)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Selection list error ({type(exc).__name__}): {exc}")


@app.get("/api/red-flags/workflow-summary")
def red_flags_workflow_summary(
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    try:
        rows = (
            db.query(TenantRedFlagSelection.approval_status, func.count(TenantRedFlagSelection.id))
            .filter(
                TenantRedFlagSelection.tenant_id == auth.tenant_id,
                TenantRedFlagSelection.is_deleted.is_(False),
            )
            .group_by(TenantRedFlagSelection.approval_status)
            .all()
        )
        counts = {str(status): int(count) for status, count in rows}
        stages = ["draft", "pending_approval", "approved", "rejected", "returned"]
        items = [{"stage": stage, "count": int(counts.get(stage, 0))} for stage in stages]
        total = sum(item["count"] for item in items)
        return {
            "success": True,
            "tenant_id": auth.tenant_id,
            "total": total,
            "data": items,
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/red-flags/workspace-policy")
def red_flags_workspace_policy(
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    try:
        role_codes = _get_user_tenant_role_codes(db, auth.tenant_id, auth.user_email)
        workflow_payload, workflow_source = _get_active_workflow_payload_safe(
            db,
            auth.tenant_id,
            module_code="red_flags",
            entity_type=_RED_FLAGS_WORKFLOW_ENTITY_TYPE,
        )
        states = workflow_payload.get("states") or []
        transitions = workflow_payload.get("transitions") or []
        terminal_states = {
            str(s.get("state_code")).strip()
            for s in states
            if bool(s.get("is_terminal"))
        }

        actions_by_state: dict[str, list[dict[str, object]]] = {}
        state_capabilities_map = _workflow_state_capability_map(states)
        user_capabilities = _workflow_user_capabilities(states, transitions, role_codes)
        editable_states = sorted(
            [state_code for state_code, caps in state_capabilities_map.items() if "selection_edit" in caps]
        )
        allowed = _allowed_transitions_for_user(workflow_payload, role_codes)
        for t in allowed:
            from_state = str(t.get("from_state_code", "")).strip()
            if not from_state:
                continue
            actions_by_state.setdefault(from_state, []).append(
                {
                    "transition_code": str(t.get("transition_code", "")).strip(),
                    "to_state_code": str(t.get("to_state_code", "")).strip(),
                    "requires_comment": bool(t.get("requires_comment")),
                }
            )

        sections = {
            "catalog": {"visible": "catalog_view" in user_capabilities},
            "in_flight": {
                "visible": bool(actions_by_state) or ("in_flight_view" in user_capabilities) or ("approval_review" in user_capabilities)
            },
            "completed": {"visible": ("completed_view" in user_capabilities) or ("audit_view" in user_capabilities)},
        }

        return {
            "success": True,
            "tenant_id": auth.tenant_id,
            "module_code": "red_flags",
            "entity_type": _RED_FLAGS_WORKFLOW_ENTITY_TYPE,
            "user_email": auth.user_email,
            "role_codes": sorted(role_codes),
            "workflow_source": workflow_source,
            "workflow": {
                "states": states,
                "transitions": transitions,
            },
            "sections": sections,
            "capabilities": {
                "actions_by_state": actions_by_state,
                "state_capabilities": {k: sorted(v) for k, v in state_capabilities_map.items()},
                "user_capabilities": sorted(user_capabilities),
                "editable_states": editable_states,
                "terminal_states": sorted([s for s in terminal_states if s]),
            },
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/red-flags/workspace-data")
def red_flags_workspace_data(
    business_unit_id: int | None = None,
    approval_status: str | None = None,
    relevance_status: str | None = None,
    include_deleted: bool = False,
    include_catalog: bool = True,
    catalog_business_unit_id: int | None = Query(default=None, ge=1),
    catalog_source_name: str | None = None,
    catalog_category: str | None = None,
    catalog_product: str | None = None,
    catalog_service: str | None = None,
    catalog_q: str | None = None,
    catalog_limit: int = Query(default=10, ge=1, le=200),
    catalog_offset: int = Query(default=0, ge=0),
    assistant_ids: str | None = None,
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    try:
        role_codes = _get_user_tenant_role_codes(db, auth.tenant_id, auth.user_email)
        workflow_payload, workflow_source = _get_active_workflow_payload_safe(
            db,
            auth.tenant_id,
            module_code="red_flags",
            entity_type=_RED_FLAGS_WORKFLOW_ENTITY_TYPE,
        )
        states = workflow_payload.get("states") or []
        transitions = workflow_payload.get("transitions") or []
        terminal_states = {
            str(s.get("state_code", "")).strip()
            for s in states
            if bool(s.get("is_terminal"))
        }
        state_capabilities_map = _workflow_state_capability_map(states)
        accessible_state_codes = _workflow_accessible_state_codes(states, transitions, role_codes)
        editable_states = {
            state_code
            for state_code, caps in state_capabilities_map.items()
            if "selection_edit" in caps
        }

        selection_result = list_red_flag_selections(
            business_unit_id=business_unit_id,
            approval_status=approval_status,
            relevance_status=relevance_status,
            include_deleted=include_deleted,
            auth=auth,
            db=db,
        )
        raw_rows = list(selection_result.data or [])

        in_flight_data: list[dict[str, object]] = []
        completed_data: list[dict[str, object]] = []

        for row in raw_rows:
            if hasattr(row, "model_dump"):
                row_dict = row.model_dump()
            elif hasattr(row, "dict"):
                row_dict = row.dict()
            else:
                row_dict = dict(row)  # type: ignore[arg-type]

            state_code = str(row_dict.get("approval_status", "")).strip()
            transition_actions = _allowed_transitions_for_user(
                workflow_payload,
                role_codes,
                from_state=state_code,
            )
            allowed_actions: list[dict[str, object]] = []
            for transition in transition_actions:
                endpoint, label = _selection_action_from_to_state(str(transition.get("to_state_code", "")).strip())
                if not endpoint:
                    continue
                allowed_actions.append(
                    {
                        "kind": "transition",
                        "action": endpoint,
                        "label": label,
                        "to_state_code": str(transition.get("to_state_code", "")).strip(),
                        "transition_code": str(transition.get("transition_code", "")).strip(),
                        "requires_comment": bool(transition.get("requires_comment")),
                    }
                )

            if state_code in editable_states and state_code in accessible_state_codes:
                allowed_actions.append({"kind": "record", "action": "edit", "label": "Edit"})
                allowed_actions.append({"kind": "record", "action": "delete", "label": "Delete"})

            row_dict["allowed_actions"] = allowed_actions
            if state_code in terminal_states:
                completed_data.append(row_dict)
            else:
                in_flight_data.append(row_dict)

        catalog_payload: dict[str, object] = {
            "success": True,
            "total": 0,
            "limit": catalog_limit,
            "offset": catalog_offset,
            "data": [],
        }
        if include_catalog:
            catalog_payload = list_red_flags_catalog_for_tenant(
                business_unit_id=catalog_business_unit_id,
                source_name=catalog_source_name,
                category=catalog_category,
                product=catalog_product,
                service=catalog_service,
                assistant_ids=assistant_ids,
                q=catalog_q,
                limit=catalog_limit,
                offset=catalog_offset,
                auth=auth,
                db=db,
            )

        return {
            "success": True,
            "tenant_id": auth.tenant_id,
            "workflow_source": workflow_source,
            "workflow": {
                "states": states,
                "terminal_states": sorted([s for s in terminal_states if s]),
                "state_capabilities": {
                    str(s.get("state_code", "")).strip(): [
                        str(c).strip()
                        for c in (s.get("capabilities") or [])
                        if str(c).strip()
                    ]
                    for s in states
                    if str(s.get("state_code", "")).strip()
                },
                "user_capabilities": sorted(_workflow_user_capabilities(states, transitions, role_codes)),
            },
            "role_codes": sorted(role_codes),
            "catalog": catalog_payload,
            "in_flight": {
                "total": len(in_flight_data),
                "data": in_flight_data,
            },
            "completed": {
                "total": len(completed_data),
                "data": completed_data,
            },
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


def _describe_selection_action(action: str) -> str:
    labels = {
        "selection_created": "Selection created",
        "selection_updated": "Selection updated",
        "selection_submitted": "Submitted for approval",
        "selection_approved": "Approved",
        "selection_rejected": "Rejected",
        "selection_returned": "Returned for updates",
        "selection_deleted": "Logically deleted",
    }
    key = (action or "").strip().lower()
    if key in labels:
        return labels[key]
    fallback = key.replace("_", " ").strip()
    return fallback.title() if fallback else "Unknown action"


@app.get("/api/red-flags/selections/{selection_id}/audit-trail")
def get_red_flag_selection_audit_trail(
    selection_id: int,
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    try:
        selection = _get_selection_or_404(db, selection_id, auth.tenant_id)
        rows = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.module_code == "red_flags",
                AuditEvent.entity_type == "tenant_red_flag_selection",
                AuditEvent.entity_id == selection.id,
                AuditEvent.tenant_id == auth.tenant_id,
            )
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .all()
        )

        items: list[dict[str, object]] = []
        for row in rows:
            payload: dict[str, object] = {}
            raw_payload = row.event_payload_json
            if raw_payload:
                try:
                    parsed = json.loads(raw_payload)
                    if isinstance(parsed, dict):
                        payload = parsed
                except Exception:
                    payload = {}
            comment = payload.get("comment")
            items.append(
                {
                    "id": int(row.id),
                    "selection_id": int(selection.id),
                    "timestamp": row.created_at.isoformat() if row.created_at else None,
                    "user": row.actor_email or "",
                    "action": row.action,
                    "action_description": _describe_selection_action(row.action),
                    "comment": str(comment).strip() if comment is not None else "",
                }
            )

        return {
            "success": True,
            "selection_id": int(selection.id),
            "total": len(items),
            "data": items,
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Selection audit trail error ({type(exc).__name__}): {exc}")


@app.get("/api/red-flags/business-units", response_model=list[BusinessUnitOut])
def list_red_flag_business_units(
    include_inactive: bool = False,
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    try:
        q = db.query(BusinessUnit).filter(BusinessUnit.tenant_id == auth.tenant_id)
        if not include_inactive:
            q = q.filter(BusinessUnit.status == "active")
        rows = q.order_by(BusinessUnit.code.asc(), BusinessUnit.id.asc()).all()
        return [_serialize_business_unit(r) for r in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/red-flags/catalog")
def list_red_flags_catalog_for_tenant(
    business_unit_id: int | None = Query(default=None, ge=1),
    source_name: str | None = None,
    category: str | None = None,
    product: str | None = None,
    service: str | None = None,
    assistant_ids: str | None = None,
    q: str | None = None,
    limit: int = Query(default=10, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    try:
        shared_assistant_ids: set[int] = set()
        tenant_assistant_ids: set[int] = set()
        assistant_filter_applied = bool((assistant_ids or "").strip())
        if assistant_filter_applied:
            for part in str(assistant_ids or "").split(","):
                raw = part.strip().upper()
                if not raw:
                    continue
                if raw.startswith("RF-"):
                    num = raw[3:]
                    if num.isdigit():
                        shared_assistant_ids.add(int(num))
                    continue
                if raw.startswith("TRF-"):
                    num = raw[4:]
                    if num.isdigit():
                        tenant_assistant_ids.add(int(num))
                    continue
                if raw.isdigit():
                    shared_assistant_ids.add(int(raw))

        if business_unit_id is not None:
            bu_exists = (
                db.query(BusinessUnit.id)
                .filter(
                    BusinessUnit.id == business_unit_id,
                    BusinessUnit.tenant_id == auth.tenant_id,
                )
                .first()
            )
            if not bu_exists:
                raise HTTPException(status_code=404, detail="Business unit not found for tenant.")

        shared_query = db.query(
            literal("shared").label("flag_source"),
            RedFlag.id.label("shared_red_flag_id"),
            literal(None, type_=Integer()).label("tenant_red_flag_id"),
            SourceDocument.source_name.label("source_name"),
            RedFlag.category.label("category"),
            RedFlag.severity.label("severity"),
            RedFlag.text.label("text"),
            RedFlag.confidence_score.label("confidence_score"),
            RedFlag.product_tags_json.label("product_tags_json"),
            RedFlag.service_tags_json.label("service_tags_json"),
            RedFlag.created_at.label("created_at"),
        ).outerjoin(SourceDocument, SourceDocument.id == RedFlag.document_id)
        if source_name:
            needle = f"%{source_name.strip().lower()}%"
            shared_query = shared_query.filter(func.lower(func.coalesce(SourceDocument.source_name, "")).like(needle))
        if category:
            needle = f"%{category.strip().lower()}%"
            shared_query = shared_query.filter(func.lower(RedFlag.category).like(needle))
        if product:
            needle = f"%{product.strip().lower()}%"
            shared_query = shared_query.filter(func.lower(func.coalesce(RedFlag.product_tags_json, "")).like(needle))
        if service:
            needle = f"%{service.strip().lower()}%"
            shared_query = shared_query.filter(func.lower(func.coalesce(RedFlag.service_tags_json, "")).like(needle))
        if q:
            needle = f"%{q.strip().lower()}%"
            shared_query = shared_query.filter(
                func.lower(func.coalesce(RedFlag.text, "")).like(needle)
                | func.lower(func.coalesce(RedFlag.category, "")).like(needle)
            )
        if assistant_filter_applied:
            if shared_assistant_ids:
                shared_query = shared_query.filter(RedFlag.id.in_(list(shared_assistant_ids)))
            else:
                shared_query = shared_query.filter(literal(False))

        tenant_query = db.query(
            literal("tenant").label("flag_source"),
            literal(None, type_=Integer()).label("shared_red_flag_id"),
            TenantRedFlag.id.label("tenant_red_flag_id"),
            literal("Tenant Added").label("source_name"),
            TenantRedFlag.category.label("category"),
            TenantRedFlag.severity.label("severity"),
            TenantRedFlag.text.label("text"),
            literal(None, type_=Integer()).label("confidence_score"),
            TenantRedFlag.product_tags_json.label("product_tags_json"),
            TenantRedFlag.service_tags_json.label("service_tags_json"),
            TenantRedFlag.created_at.label("created_at"),
        ).filter(
            TenantRedFlag.tenant_id == auth.tenant_id,
            TenantRedFlag.is_deleted.is_(False),
        )
        if source_name:
            # Tenant-added flags are not tied to source_documents.
            needle = source_name.strip().lower()
            if "tenant" not in needle:
                tenant_query = tenant_query.filter(literal(False))
        if category:
            needle = f"%{category.strip().lower()}%"
            tenant_query = tenant_query.filter(func.lower(TenantRedFlag.category).like(needle))
        if product:
            needle = f"%{product.strip().lower()}%"
            tenant_query = tenant_query.filter(func.lower(func.coalesce(TenantRedFlag.product_tags_json, "")).like(needle))
        if service:
            needle = f"%{service.strip().lower()}%"
            tenant_query = tenant_query.filter(func.lower(func.coalesce(TenantRedFlag.service_tags_json, "")).like(needle))
        if q:
            needle = f"%{q.strip().lower()}%"
            tenant_query = tenant_query.filter(
                func.lower(func.coalesce(TenantRedFlag.text, "")).like(needle)
                | func.lower(func.coalesce(TenantRedFlag.category, "")).like(needle)
            )
        if assistant_filter_applied:
            if tenant_assistant_ids:
                tenant_query = tenant_query.filter(TenantRedFlag.id.in_(list(tenant_assistant_ids)))
            else:
                tenant_query = tenant_query.filter(literal(False))

        catalog_subquery = shared_query.union_all(tenant_query).subquery("catalog_flags")
        total = db.query(func.count()).select_from(catalog_subquery).scalar() or 0
        sort_id = func.coalesce(catalog_subquery.c.shared_red_flag_id, catalog_subquery.c.tenant_red_flag_id)
        rows = (
            db.query(catalog_subquery)
            .order_by(catalog_subquery.c.created_at.desc(), sort_id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        selected_lookup: dict[tuple[str, int], dict[str, object]] = {}
        if business_unit_id is not None and rows:
            shared_ids = [int(r.shared_red_flag_id) for r in rows if r.shared_red_flag_id is not None]
            tenant_ids = [int(r.tenant_red_flag_id) for r in rows if r.tenant_red_flag_id is not None]
            selection_rows = (
                db.query(
                    TenantRedFlagSelection.id,
                    TenantRedFlagSelection.shared_red_flag_id,
                    TenantRedFlagSelection.tenant_red_flag_id,
                    TenantRedFlagSelection.approval_status,
                    TenantRedFlagSelection.relevance_status,
                )
                .filter(
                    TenantRedFlagSelection.tenant_id == auth.tenant_id,
                    TenantRedFlagSelection.business_unit_id == business_unit_id,
                    TenantRedFlagSelection.is_deleted.is_(False),
                    (
                        TenantRedFlagSelection.shared_red_flag_id.in_(shared_ids)
                        if shared_ids
                        else literal(False)
                    )
                    | (
                        TenantRedFlagSelection.tenant_red_flag_id.in_(tenant_ids)
                        if tenant_ids
                        else literal(False)
                    ),
                )
                .all()
            )
            for s in selection_rows:
                if s.shared_red_flag_id is not None:
                    selected_lookup[("shared", int(s.shared_red_flag_id))] = {
                        "selection_id": int(s.id),
                        "approval_status": str(s.approval_status),
                        "relevance_status": str(s.relevance_status),
                    }
                if s.tenant_red_flag_id is not None:
                    selected_lookup[("tenant", int(s.tenant_red_flag_id))] = {
                        "selection_id": int(s.id),
                        "approval_status": str(s.approval_status),
                        "relevance_status": str(s.relevance_status),
                    }

        data = [
            {
                "id": (
                    f"RF-{int(r.shared_red_flag_id)}"
                    if r.shared_red_flag_id is not None
                    else f"TRF-{int(r.tenant_red_flag_id)}"
                ),
                "flag_source": str(r.flag_source),
                "shared_red_flag_id": int(r.shared_red_flag_id) if r.shared_red_flag_id is not None else None,
                "tenant_red_flag_id": int(r.tenant_red_flag_id) if r.tenant_red_flag_id is not None else None,
                "source_name": str(r.source_name) if r.source_name else None,
                "category": r.category,
                "severity": r.severity,
                "text": r.text,
                "confidence_score": r.confidence_score,
                "product_tags": _parse_tags_json(r.product_tags_json),
                "service_tags": _parse_tags_json(r.service_tags_json),
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "already_selected": (
                    ("shared", int(r.shared_red_flag_id)) in selected_lookup
                    if r.shared_red_flag_id is not None
                    else (("tenant", int(r.tenant_red_flag_id)) in selected_lookup)
                )
                if business_unit_id is not None
                else False,
                "existing_selection_id": (
                    selected_lookup.get(("shared", int(r.shared_red_flag_id)), {}).get("selection_id")
                    if r.shared_red_flag_id is not None
                    else selected_lookup.get(("tenant", int(r.tenant_red_flag_id)), {}).get("selection_id")
                )
                if business_unit_id is not None
                else None,
                "existing_selection_approval_status": (
                    selected_lookup.get(("shared", int(r.shared_red_flag_id)), {}).get("approval_status")
                    if r.shared_red_flag_id is not None
                    else selected_lookup.get(("tenant", int(r.tenant_red_flag_id)), {}).get("approval_status")
                )
                if business_unit_id is not None
                else None,
            }
            for r in rows
        ]
        return {
            "success": True,
            "tenant_id": auth.tenant_id,
            "total": int(total),
            "limit": int(limit),
            "offset": int(offset),
            "data": data,
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/red-flags/catalog-filters")
def list_red_flags_catalog_filters_for_tenant(
    auth: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
    db: Session = Depends(get_db),
):
    try:
        categories: set[str] = set()
        products: set[str] = set()
        services: set[str] = set()
        sources: set[str] = set()

        rows = db.query(RedFlag.category, RedFlag.product_tags_json, RedFlag.service_tags_json).all()
        for category, product_tags_json, service_tags_json in rows:
            if category and category.strip():
                categories.add(category.strip())
            for product in _parse_tags_json(product_tags_json):
                if product and product.strip():
                    products.add(product.strip())
            for service in _parse_tags_json(service_tags_json):
                if service and service.strip():
                    services.add(service.strip())
        source_rows = (
            db.query(SourceDocument.source_name)
            .join(RedFlag, RedFlag.document_id == SourceDocument.id)
            .distinct()
            .all()
        )
        for (source_name_value,) in source_rows:
            if source_name_value and str(source_name_value).strip():
                sources.add(str(source_name_value).strip())

        tenant_rows = (
            db.query(TenantRedFlag.category, TenantRedFlag.product_tags_json, TenantRedFlag.service_tags_json)
            .filter(
                TenantRedFlag.tenant_id == auth.tenant_id,
                TenantRedFlag.is_deleted.is_(False),
            )
            .all()
        )
        for category, product_tags_json, service_tags_json in tenant_rows:
            if category and category.strip():
                categories.add(category.strip())
            for product in _parse_tags_json(product_tags_json):
                if product and product.strip():
                    products.add(product.strip())
            for service in _parse_tags_json(service_tags_json):
                if service and service.strip():
                    services.add(service.strip())

        return {
            "success": True,
            "tenant_id": auth.tenant_id,
            "sources": sorted(sources, key=lambda v: v.lower()),
            "categories": sorted(categories, key=lambda v: v.lower()),
            "products": sorted(products, key=lambda v: v.lower()),
            "services": sorted(services, key=lambda v: v.lower()),
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/red-flags/catalog-assistant/seed-questions")
def get_catalog_assistant_seed_questions(
    business_unit_id: int = Query(..., ge=1),
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    try:
        bu = (
            db.query(BusinessUnit)
            .filter(
                BusinessUnit.id == business_unit_id,
                BusinessUnit.tenant_id == auth.tenant_id,
            )
            .first()
        )
        if not bu:
            raise HTTPException(status_code=404, detail="Business unit not found for tenant.")

        return {
            "success": True,
            "business_unit_id": int(business_unit_id),
            "questions": [
                f"We are {bu.name}. Which catalog red flags are most relevant to our products and services?",
                "We operate in higher-risk geographies. Which catalog red flags mention geography or cross-border patterns?",
                "Which catalog red flags are most relevant for money services, correspondent banking, or cash-intensive activity?",
                "Which catalog red flags should we prioritize first for analyst review and why?",
                "Which catalog red flags appear to align with sanctions evasion or terrorist financing typologies?",
            ],
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/red-flags/catalog-assistant/chat")
def red_flag_catalog_assistant_chat(
    payload: CatalogAssistantChatRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    try:
        bu = (
            db.query(BusinessUnit)
            .filter(
                BusinessUnit.id == payload.business_unit_id,
                BusinessUnit.tenant_id == auth.tenant_id,
            )
            .first()
        )
        if not bu:
            raise HTTPException(status_code=404, detail="Business unit not found for tenant.")

        shared_query = db.query(
            literal("shared").label("flag_source"),
            RedFlag.id.label("shared_red_flag_id"),
            literal(None, type_=Integer()).label("tenant_red_flag_id"),
            SourceDocument.source_name.label("source_name"),
            RedFlag.category.label("category"),
            RedFlag.severity.label("severity"),
            RedFlag.text.label("text"),
            RedFlag.product_tags_json.label("product_tags_json"),
            RedFlag.service_tags_json.label("service_tags_json"),
            RedFlag.created_at.label("created_at"),
        ).outerjoin(SourceDocument, SourceDocument.id == RedFlag.document_id)

        tenant_query = db.query(
            literal("tenant").label("flag_source"),
            literal(None, type_=Integer()).label("shared_red_flag_id"),
            TenantRedFlag.id.label("tenant_red_flag_id"),
            literal("Tenant Added").label("source_name"),
            TenantRedFlag.category.label("category"),
            TenantRedFlag.severity.label("severity"),
            TenantRedFlag.text.label("text"),
            TenantRedFlag.product_tags_json.label("product_tags_json"),
            TenantRedFlag.service_tags_json.label("service_tags_json"),
            TenantRedFlag.created_at.label("created_at"),
        ).filter(
            TenantRedFlag.tenant_id == auth.tenant_id,
            TenantRedFlag.is_deleted.is_(False),
        )

        catalog_subquery = shared_query.union_all(tenant_query).subquery("catalog_assistant_flags")
        sort_id = func.coalesce(catalog_subquery.c.shared_red_flag_id, catalog_subquery.c.tenant_red_flag_id)
        rows = (
            db.query(catalog_subquery)
            .order_by(catalog_subquery.c.created_at.desc(), sort_id.desc())
            .limit(300)
            .all()
        )

        tokens = _catalog_assistant_tokens(payload.message)
        if not tokens:
            return {
                "success": True,
                "message": "Please provide a bit more detail (products, services, geography, regulator, customer types, or FI type).",
                "token_count": 0,
                "mode": "rules",
                "matches": [],
            }

        scored: list[dict[str, object]] = []
        for row in rows:
            products = _parse_tags_json(row.product_tags_json)
            services = _parse_tags_json(row.service_tags_json)
            haystack = " ".join(
                [
                    str(row.category or ""),
                    str(row.severity or ""),
                    str(row.text or ""),
                    str(row.source_name or ""),
                    " ".join(products),
                    " ".join(services),
                ]
            ).lower()

            score = 0
            reasons: list[str] = []
            for token in tokens:
                if token not in haystack:
                    continue
                token_score = 1
                if row.category and token in str(row.category).lower():
                    token_score += 3
                if row.text and token in str(row.text).lower():
                    token_score += 2
                if any(token in p.lower() for p in products):
                    token_score += 2
                if any(token in s.lower() for s in services):
                    token_score += 2
                score += token_score
                reasons.append(token)

            if score <= 0:
                continue

            is_shared = row.shared_red_flag_id is not None
            score += 1 if str(row.severity or "").lower() == "high" else 0
            scored.append(
                {
                    "score": int(score),
                    "match_terms": sorted(set(reasons)),
                    "id": (
                        f"RF-{int(row.shared_red_flag_id)}"
                        if is_shared
                        else f"TRF-{int(row.tenant_red_flag_id)}"
                    ),
                    "flag_source": str(row.flag_source),
                    "shared_red_flag_id": int(row.shared_red_flag_id) if is_shared else None,
                    "tenant_red_flag_id": int(row.tenant_red_flag_id) if not is_shared else None,
                    "source_name": str(row.source_name) if row.source_name else None,
                    "category": str(row.category or ""),
                    "severity": str(row.severity or ""),
                    "text": str(row.text or ""),
                    "product_tags": products,
                    "service_tags": services,
                }
            )

        scored.sort(key=lambda r: (int(r["score"]), str(r.get("severity", "") == "high")), reverse=True)
        top_matches = scored[:10]
        unique_categories = sorted({str(r.get("category", "")) for r in top_matches if str(r.get("category", "")).strip()})
        unique_sources = sorted({str(r.get("source_name", "")) for r in top_matches if str(r.get("source_name", "")).strip()})

        mode = "rules"
        if not top_matches:
            reply = (
                "I could not find a strong match in the current catalog. "
                "Try adding more specifics about products, services, geographies, regulator, or customer types."
            )
        else:
            reply = (
                f"I found {len(top_matches)} catalog red flag matches for your context. "
                f"Top categories: {', '.join(unique_categories[:4]) or 'n/a'}. "
                f"Top sources: {', '.join(unique_sources[:3]) or 'n/a'}."
            )
            llm_reply, llm_ids = _openai_catalog_assistant_reply(
                user_message=payload.message,
                business_unit_name=str(bu.name or f"BU-{bu.id}"),
                candidates=top_matches,
            )
            if llm_ids:
                by_id = {str(row.get("id")): row for row in top_matches}
                ordered: list[dict[str, object]] = []
                seen_ids: set[str] = set()
                for rid in llm_ids:
                    row = by_id.get(rid)
                    if not row:
                        continue
                    ordered.append(row)
                    seen_ids.add(rid)
                for row in top_matches:
                    rid = str(row.get("id"))
                    if rid not in seen_ids:
                        ordered.append(row)
                top_matches = ordered[:10]
            if llm_reply:
                reply = llm_reply
                mode = "openai"

        return {
            "success": True,
            "message": reply,
            "token_count": len(tokens),
            "tokens": tokens,
            "mode": mode,
            "matches": top_matches,
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/red-flags/selections", response_model=RedFlagSelectionOut)
def create_red_flag_selection(
    request: Request,
    payload: RedFlagSelectionCreateRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    _ensure_tenant_red_flag_table()
    now = datetime.now(timezone.utc)
    actor_user_id = _resolve_actor_user_id(db, auth)
    allowed_relevance = {"in_scope", "out_of_scope", "needs_review"}
    if payload.relevance_status not in allowed_relevance:
        raise HTTPException(status_code=400, detail=f"relevance_status must be one of: {sorted(allowed_relevance)}")
    if not payload.shared_red_flag_id and not payload.tenant_red_flag_id:
        raise HTTPException(status_code=400, detail="Provide shared_red_flag_id or tenant_red_flag_id.")
    if payload.shared_red_flag_id and payload.tenant_red_flag_id:
        raise HTTPException(status_code=400, detail="Provide only one of shared_red_flag_id or tenant_red_flag_id.")

    bu = (
        db.query(BusinessUnit)
        .filter(BusinessUnit.id == payload.business_unit_id, BusinessUnit.tenant_id == auth.tenant_id, BusinessUnit.status == "active")
        .first()
    )
    if not bu:
        raise HTTPException(status_code=404, detail="Business unit not found for tenant.")

    if payload.shared_red_flag_id is not None:
        red_flag = db.query(RedFlag.id).filter(RedFlag.id == payload.shared_red_flag_id).first()
        if not red_flag:
            raise HTTPException(status_code=404, detail="Shared red flag not found.")
    if payload.tenant_red_flag_id is not None:
        tenant_red_flag = (
            db.query(TenantRedFlag.id)
            .filter(
                TenantRedFlag.id == payload.tenant_red_flag_id,
                TenantRedFlag.tenant_id == auth.tenant_id,
                TenantRedFlag.is_deleted.is_(False),
            )
            .first()
        )
        if not tenant_red_flag:
            raise HTTPException(status_code=404, detail="Tenant red flag not found.")

    existing_q = db.query(TenantRedFlagSelection.id).filter(
        TenantRedFlagSelection.tenant_id == auth.tenant_id,
        TenantRedFlagSelection.business_unit_id == payload.business_unit_id,
        TenantRedFlagSelection.is_deleted.is_(False),
    )
    if payload.shared_red_flag_id is not None:
        existing_q = existing_q.filter(TenantRedFlagSelection.shared_red_flag_id == payload.shared_red_flag_id)
    else:
        existing_q = existing_q.filter(TenantRedFlagSelection.tenant_red_flag_id == payload.tenant_red_flag_id)
    existing = existing_q.first()
    if existing:
        raise HTTPException(status_code=409, detail="Selection already exists for this business unit and red flag.")

    try:
        selection = TenantRedFlagSelection(
            tenant_id=auth.tenant_id,
            business_unit_id=payload.business_unit_id,
            shared_red_flag_id=payload.shared_red_flag_id,
            tenant_red_flag_id=payload.tenant_red_flag_id,
            relevance_status=payload.relevance_status,
            approval_status="draft",
            rationale=payload.rationale,
            analyst_user_id=actor_user_id,
            approver_user_id=None,
            submitted_at=None,
            approved_at=None,
            is_deleted=False,
            deleted_at=None,
            deleted_by_user_id=None,
            created_at=now,
            updated_at=now,
            created_by_user_id=actor_user_id,
            updated_by_user_id=actor_user_id,
        )
        db.add(selection)
        db.flush()
        _record_selection_event(
            db,
            selection,
            actor_user_id,
            event_type="selection_created",
            from_state=None,
            to_state="draft",
            payload={"rationale": payload.rationale, "relevance_status": payload.relevance_status},
        )
        _record_audit_event(
            db,
            module_code="red_flags",
            action="selection_created",
            tenant_id=selection.tenant_id,
            entity_type="tenant_red_flag_selection",
            entity_id=selection.id,
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={
                "business_unit_id": selection.business_unit_id,
                "shared_red_flag_id": selection.shared_red_flag_id,
                "tenant_red_flag_id": selection.tenant_red_flag_id,
                "relevance_status": selection.relevance_status,
            },
        )
        db.commit()
        db.refresh(selection)
        return _to_selection_out(db, selection)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/red-flags/selections/custom", response_model=RedFlagSelectionOut)
def create_custom_red_flag_selection(
    request: Request,
    payload: TenantRedFlagSelectionCreateRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    _ensure_tenant_red_flag_table()
    now = datetime.now(timezone.utc)
    actor_user_id = _resolve_actor_user_id(db, auth)
    allowed_relevance = {"in_scope", "out_of_scope", "needs_review"}
    if payload.relevance_status not in allowed_relevance:
        raise HTTPException(status_code=400, detail=f"relevance_status must be one of: {sorted(allowed_relevance)}")

    category = (payload.category or "").strip()
    severity = (payload.severity or "").strip()
    text = (payload.text or "").strip()
    if not category:
        raise HTTPException(status_code=400, detail="category is required.")
    if not severity:
        raise HTTPException(status_code=400, detail="severity is required.")
    if not text:
        raise HTTPException(status_code=400, detail="text is required.")

    bu = (
        db.query(BusinessUnit)
        .filter(BusinessUnit.id == payload.business_unit_id, BusinessUnit.tenant_id == auth.tenant_id, BusinessUnit.status == "active")
        .first()
    )
    if not bu:
        raise HTTPException(status_code=404, detail="Business unit not found for tenant.")

    norm_products = _normalize_tags(payload.product_tags)
    norm_services = _normalize_tags(payload.service_tags)

    try:
        existing_tenant_flag = (
            db.query(TenantRedFlag)
            .filter(
                TenantRedFlag.tenant_id == auth.tenant_id,
                TenantRedFlag.is_deleted.is_(False),
                func.lower(TenantRedFlag.category) == category.lower(),
                func.lower(TenantRedFlag.text) == text.lower(),
            )
            .first()
        )

        if existing_tenant_flag:
            tenant_flag = existing_tenant_flag
            tenant_flag.severity = severity
            tenant_flag.product_tags_json = json.dumps(norm_products, separators=(",", ":"))
            tenant_flag.service_tags_json = json.dumps(norm_services, separators=(",", ":"))
            tenant_flag.updated_at = now
            tenant_flag.updated_by_user_id = actor_user_id
        else:
            tenant_flag = TenantRedFlag(
                tenant_id=auth.tenant_id,
                category=category,
                severity=severity,
                text=text,
                product_tags_json=json.dumps(norm_products, separators=(",", ":")),
                service_tags_json=json.dumps(norm_services, separators=(",", ":")),
                created_at=now,
                updated_at=now,
                created_by_user_id=actor_user_id,
                updated_by_user_id=actor_user_id,
                is_deleted=False,
                deleted_at=None,
                deleted_by_user_id=None,
            )
            db.add(tenant_flag)
            db.flush()
            _record_audit_event(
                db,
                module_code="red_flags",
                action="tenant_red_flag_created",
                tenant_id=auth.tenant_id,
                entity_type="tenant_red_flag",
                entity_id=int(tenant_flag.id),
                actor_user_id=actor_user_id,
                actor_email=auth.user_email,
                request=request,
                payload={"category": category, "severity": severity},
            )

        existing_selection = (
            db.query(TenantRedFlagSelection.id)
            .filter(
                TenantRedFlagSelection.tenant_id == auth.tenant_id,
                TenantRedFlagSelection.business_unit_id == payload.business_unit_id,
                TenantRedFlagSelection.tenant_red_flag_id == tenant_flag.id,
                TenantRedFlagSelection.is_deleted.is_(False),
            )
            .first()
        )
        if existing_selection:
            raise HTTPException(status_code=409, detail="Selection already exists for this business unit and tenant red flag.")

        selection = TenantRedFlagSelection(
            tenant_id=auth.tenant_id,
            business_unit_id=payload.business_unit_id,
            shared_red_flag_id=None,
            tenant_red_flag_id=tenant_flag.id,
            relevance_status=payload.relevance_status,
            approval_status="draft",
            rationale=payload.rationale,
            analyst_user_id=actor_user_id,
            approver_user_id=None,
            submitted_at=None,
            approved_at=None,
            is_deleted=False,
            deleted_at=None,
            deleted_by_user_id=None,
            created_at=now,
            updated_at=now,
            created_by_user_id=actor_user_id,
            updated_by_user_id=actor_user_id,
        )
        db.add(selection)
        db.flush()

        _record_selection_event(
            db,
            selection,
            actor_user_id,
            event_type="selection_created",
            from_state=None,
            to_state="draft",
            payload={
                "rationale": payload.rationale,
                "relevance_status": payload.relevance_status,
                "tenant_red_flag_id": int(tenant_flag.id),
            },
        )
        _record_audit_event(
            db,
            module_code="red_flags",
            action="selection_created",
            tenant_id=selection.tenant_id,
            entity_type="tenant_red_flag_selection",
            entity_id=selection.id,
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={
                "business_unit_id": selection.business_unit_id,
                "tenant_red_flag_id": int(tenant_flag.id),
                "relevance_status": selection.relevance_status,
            },
        )
        db.commit()
        db.refresh(selection)
        return _to_selection_out(db, selection)
    except HTTPException:
        db.rollback()
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.patch("/api/red-flags/selections/{selection_id}", response_model=RedFlagSelectionOut)
def update_red_flag_selection(
    request: Request,
    selection_id: int,
    payload: RedFlagSelectionUpdateRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    actor_user_id = _resolve_actor_user_id(db, auth)
    selection = _get_selection_or_404(db, selection_id, auth.tenant_id)
    if selection.is_deleted:
        raise HTTPException(status_code=400, detail="Selection is deleted.")
    if selection.approval_status not in {"draft", "returned", "rejected"}:
        raise HTTPException(status_code=409, detail="Only draft/returned/rejected selections can be edited.")

    if payload.relevance_status is not None and payload.relevance_status not in {"in_scope", "out_of_scope", "needs_review"}:
        raise HTTPException(status_code=400, detail="Invalid relevance_status.")

    old_state = selection.approval_status
    if payload.relevance_status is not None:
        selection.relevance_status = payload.relevance_status
    if payload.rationale is not None:
        selection.rationale = payload.rationale
    selection.updated_at = datetime.now(timezone.utc)
    selection.updated_by_user_id = actor_user_id
    selection.analyst_user_id = actor_user_id

    try:
        _record_selection_event(
            db,
            selection,
            actor_user_id,
            event_type="selection_updated",
            from_state=old_state,
            to_state=selection.approval_status,
            payload={"relevance_status": selection.relevance_status},
        )
        _record_audit_event(
            db,
            module_code="red_flags",
            action="selection_updated",
            tenant_id=selection.tenant_id,
            entity_type="tenant_red_flag_selection",
            entity_id=selection.id,
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"relevance_status": selection.relevance_status},
        )
        db.commit()
        db.refresh(selection)
        return _to_selection_out(db, selection)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


def _transition_selection_state(
    db: Session,
    auth: AuthContext,
    request: Request | None,
    selection_id: int,
    to_state: str,
    allowed_from: set[str],
    event_type: str,
    comment: str | None = None,
) -> RedFlagSelectionOut:
    _ensure_selection_table()
    actor_user_id = _resolve_actor_user_id(db, auth)
    selection = _get_selection_or_404(db, selection_id, auth.tenant_id)
    if selection.is_deleted:
        raise HTTPException(status_code=400, detail="Selection is deleted.")

    from_state = selection.approval_status
    role_codes = _get_user_tenant_role_codes(db, auth.tenant_id, auth.user_email)
    workflow_payload, workflow_source = _get_active_workflow_payload(
        db,
        auth.tenant_id,
        module_code="red_flags",
        entity_type=_RED_FLAGS_WORKFLOW_ENTITY_TYPE,
    )
    allowed_transitions = _allowed_transitions_for_user(
        workflow_payload,
        role_codes,
        from_state=from_state,
        to_state=to_state,
    )
    chosen_transition = allowed_transitions[0] if allowed_transitions else None

    if chosen_transition is None:
        if workflow_source == "fallback_legacy":
            if selection.approval_status not in allowed_from:
                raise HTTPException(status_code=409, detail=f"Cannot transition from {selection.approval_status} to {to_state}.")
        else:
            raise HTTPException(
                status_code=409,
                detail=f"Workflow does not allow transition from {from_state} to {to_state} for your role(s).",
            )

    if chosen_transition is not None and bool(chosen_transition.get("requires_comment")) and not (comment or "").strip():
        raise HTTPException(status_code=400, detail="A comment is required for this workflow transition.")

    now = datetime.now(timezone.utc)
    selection.approval_status = to_state
    selection.updated_at = now
    selection.updated_by_user_id = actor_user_id

    if to_state == "pending_approval":
        selection.submitted_at = now
        selection.analyst_user_id = actor_user_id
        selection.approver_user_id = None
        selection.approved_at = None
    elif to_state == "approved":
        selection.approver_user_id = actor_user_id
        selection.approved_at = now
    elif to_state in {"rejected", "returned"}:
        selection.approver_user_id = actor_user_id

    _record_selection_event(
        db,
        selection,
        actor_user_id,
        event_type=event_type,
        from_state=from_state,
        to_state=to_state,
        payload={"comment": comment},
    )
    _record_audit_event(
        db,
        module_code="red_flags",
        action=event_type,
        tenant_id=selection.tenant_id,
        entity_type="tenant_red_flag_selection",
        entity_id=selection.id,
        actor_user_id=actor_user_id,
        actor_email=auth.user_email,
        request=request,
        payload={"from_state": from_state, "to_state": to_state, "comment": comment},
    )
    db.commit()
    db.refresh(selection)
    return _to_selection_out(db, selection)


@app.post("/api/red-flags/selections/{selection_id}/submit", response_model=RedFlagSelectionOut)
def submit_red_flag_selection(
    request: Request,
    selection_id: int,
    payload: RedFlagSelectionActionRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    try:
        return _transition_selection_state(
            db=db,
            auth=auth,
            request=request,
            selection_id=selection_id,
            to_state="pending_approval",
            allowed_from={"draft", "returned", "rejected"},
            event_type="selection_submitted",
            comment=payload.comment,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/red-flags/selections/{selection_id}/approve", response_model=RedFlagSelectionOut)
def approve_red_flag_selection(
    request: Request,
    selection_id: int,
    payload: RedFlagSelectionActionRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_approver")),
    db: Session = Depends(get_db),
):
    try:
        return _transition_selection_state(
            db=db,
            auth=auth,
            request=request,
            selection_id=selection_id,
            to_state="approved",
            allowed_from={"pending_approval"},
            event_type="selection_approved",
            comment=payload.comment,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/red-flags/selections/{selection_id}/reject", response_model=RedFlagSelectionOut)
def reject_red_flag_selection(
    request: Request,
    selection_id: int,
    payload: RedFlagSelectionActionRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_approver")),
    db: Session = Depends(get_db),
):
    try:
        return _transition_selection_state(
            db=db,
            auth=auth,
            request=request,
            selection_id=selection_id,
            to_state="rejected",
            allowed_from={"pending_approval"},
            event_type="selection_rejected",
            comment=payload.comment,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/red-flags/selections/{selection_id}/return", response_model=RedFlagSelectionOut)
def return_red_flag_selection(
    request: Request,
    selection_id: int,
    payload: RedFlagSelectionActionRequest,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_approver")),
    db: Session = Depends(get_db),
):
    try:
        return _transition_selection_state(
            db=db,
            auth=auth,
            request=request,
            selection_id=selection_id,
            to_state="returned",
            allowed_from={"pending_approval"},
            event_type="selection_returned",
            comment=payload.comment,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.delete("/api/red-flags/selections/{selection_id}")
def delete_red_flag_selection(
    request: Request,
    selection_id: int,
    auth: AuthContext = Depends(require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst")),
    db: Session = Depends(get_db),
):
    _ensure_selection_table()
    actor_user_id = _resolve_actor_user_id(db, auth)
    selection = _get_selection_or_404(db, selection_id, auth.tenant_id)
    if selection.is_deleted:
        return {"success": True, "id": selection.id, "is_deleted": True}

    selection.is_deleted = True
    selection.deleted_at = datetime.now(timezone.utc)
    selection.deleted_by_user_id = actor_user_id
    selection.updated_at = selection.deleted_at
    selection.updated_by_user_id = actor_user_id

    try:
        _record_selection_event(
            db,
            selection,
            actor_user_id,
            event_type="selection_deleted",
            from_state=selection.approval_status,
            to_state=selection.approval_status,
            payload={"is_deleted": True},
        )
        _record_audit_event(
            db,
            module_code="red_flags",
            action="selection_deleted",
            tenant_id=selection.tenant_id,
            entity_type="tenant_red_flag_selection",
            entity_id=selection.id,
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"is_deleted": True},
        )
        db.commit()
        return {"success": True, "id": selection.id, "is_deleted": True}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/platform/rbac/red-flags")
def rbac_red_flags(
    _: AuthContext = Depends(
        require_tenant_permission("red_flags", "tenant_admin", "red_flag_analyst", "red_flag_approver", "read_only_audit")
    ),
):
    return {"module": "red_flags", "authorized": True}


@app.get("/api/platform/rbac/transaction-monitoring")
def rbac_transaction_monitoring(
    _: AuthContext = Depends(
        require_tenant_permission(
            "transaction_monitoring",
            "tenant_admin",
            "control_developer",
            "control_reviewer",
            "control_approver",
            "read_only_audit",
        )
    ),
):
    return {"module": "transaction_monitoring", "authorized": True}


@app.get("/api/platform/rbac/operational-reporting")
def rbac_operational_reporting(
    _: AuthContext = Depends(
        require_tenant_permission(
            "operational_reporting",
            "tenant_admin",
            "read_only_audit",
        )
    ),
):
    return {"module": "operational_reporting", "authorized": True}


@app.get("/api/platform/users/roles")
def list_tenant_users_roles(
    auth: AuthContext = Depends(require_tenant_context),
    db: Session = Depends(get_db),
):
    try:
        rows = (
            db.query(AppUser.email, Role.code)
            .join(TenantUser, and_(TenantUser.app_user_id == AppUser.id, TenantUser.tenant_id == auth.tenant_id))
            .join(TenantUserRole, TenantUserRole.tenant_user_id == TenantUser.id)
            .join(Role, Role.id == TenantUserRole.role_id)
            .order_by(AppUser.email.asc(), Role.code.asc())
            .all()
        )
        result: dict[str, list[str]] = {}
        for email, role_code in rows:
            result.setdefault(email, []).append(role_code)
        return {"tenant_id": auth.tenant_id, "users": result}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


def _ensure_role_rows(db: Session, role_codes: list[str]) -> dict[str, int]:
    codes = sorted({c.strip() for c in role_codes if c and c.strip()})
    if not codes:
        return {}

    existing = db.query(Role).filter(Role.code.in_(codes)).all()
    by_code = {r.code: int(r.id) for r in existing}
    missing = [c for c in codes if c not in by_code]
    for code in missing:
        role = Role(
            code=code,
            scope="tenant",
            description=f"Tenant role: {code}",
        )
        db.add(role)
        db.flush()
        by_code[code] = int(role.id)
    return by_code


def _ensure_default_tenant_roles(db: Session) -> None:
    existing_rows = db.query(Role.code).filter(Role.scope == "tenant").all()
    existing = {str(r[0]) for r in existing_rows}
    for code in DEFAULT_TENANT_ROLE_CODES:
        if code in existing:
            continue
        db.add(
            Role(
                code=code,
                scope="tenant",
                description=f"Tenant role: {code}",
            )
        )
    db.flush()


@app.get("/api/tenant-admin/business-units", response_model=list[BusinessUnitOut])
def list_tenant_business_units(
    include_inactive: bool = True,
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        q = db.query(BusinessUnit).filter(BusinessUnit.tenant_id == auth.tenant_id)
        if not include_inactive:
            q = q.filter(BusinessUnit.status == "active")
        rows = q.order_by(BusinessUnit.code.asc(), BusinessUnit.id.asc()).all()
        return [_serialize_business_unit(r) for r in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/tenant-admin/business-units", response_model=BusinessUnitOut)
def create_tenant_business_unit(
    request: Request,
    payload: BusinessUnitCreateRequest,
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    code = _norm_key(payload.code)
    name = " ".join(payload.name.split())
    status = payload.status.strip().lower()
    if not code:
        raise HTTPException(status_code=400, detail="Business unit code is required.")
    if not name:
        raise HTTPException(status_code=400, detail="Business unit name is required.")
    if status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="status must be active|inactive.")

    try:
        exists = (
            db.query(BusinessUnit.id)
            .filter(
                BusinessUnit.tenant_id == auth.tenant_id,
                func.lower(func.trim(BusinessUnit.code)) == code.lower(),
            )
            .first()
        )
        if exists:
            raise HTTPException(status_code=409, detail=f"Business unit code '{code}' already exists for tenant.")

        now = datetime.now(timezone.utc)
        row = BusinessUnit(
            tenant_id=auth.tenant_id,
            code=code,
            name=name,
            status=status,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="business_unit_created",
            tenant_id=auth.tenant_id,
            entity_type="business_unit",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"code": row.code, "name": row.name, "status": row.status},
        )
        db.commit()
        return _serialize_business_unit(row)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.patch("/api/tenant-admin/business-units/{business_unit_id}", response_model=BusinessUnitOut)
def update_tenant_business_unit(
    request: Request,
    business_unit_id: int,
    payload: BusinessUnitUpdateRequest,
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        row = (
            db.query(BusinessUnit)
            .filter(BusinessUnit.id == business_unit_id, BusinessUnit.tenant_id == auth.tenant_id)
            .first()
        )
        if not row:
            raise HTTPException(status_code=404, detail="Business unit not found.")

        if payload.code is not None:
            new_code = _norm_key(payload.code)
            if not new_code:
                raise HTTPException(status_code=400, detail="Business unit code cannot be empty.")
            code_conflict = (
                db.query(BusinessUnit.id)
                .filter(
                    BusinessUnit.tenant_id == auth.tenant_id,
                    BusinessUnit.id != business_unit_id,
                    func.lower(func.trim(BusinessUnit.code)) == new_code.lower(),
                )
                .first()
            )
            if code_conflict:
                raise HTTPException(status_code=409, detail=f"Business unit code '{new_code}' already exists for tenant.")
            row.code = new_code

        if payload.name is not None:
            new_name = " ".join(payload.name.split())
            if not new_name:
                raise HTTPException(status_code=400, detail="Business unit name cannot be empty.")
            row.name = new_name

        if payload.status is not None:
            new_status = payload.status.strip().lower()
            if new_status not in {"active", "inactive"}:
                raise HTTPException(status_code=400, detail="status must be active|inactive.")
            row.status = new_status

        row.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="business_unit_updated",
            tenant_id=auth.tenant_id,
            entity_type="business_unit",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"code": row.code, "name": row.name, "status": row.status},
        )
        db.commit()
        return _serialize_business_unit(row)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.delete("/api/tenant-admin/business-units/{business_unit_id}")
def deactivate_tenant_business_unit(
    request: Request,
    business_unit_id: int,
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        row = (
            db.query(BusinessUnit)
            .filter(BusinessUnit.id == business_unit_id, BusinessUnit.tenant_id == auth.tenant_id)
            .first()
        )
        if not row:
            return {"success": True, "updated": False}

        row.status = "inactive"
        row.updated_at = datetime.now(timezone.utc)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="business_unit_deactivated",
            tenant_id=auth.tenant_id,
            entity_type="business_unit",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"status": "inactive"},
        )
        db.commit()
        return {"success": True, "updated": True, "status": "inactive", "id": int(row.id)}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/tenant-admin/users", response_model=list[TenantUserOut])
def list_tenant_users(
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        rows = (
            db.query(AppUser.email, TenantUser.status, Role.code)
            .join(TenantUser, and_(TenantUser.app_user_id == AppUser.id, TenantUser.tenant_id == auth.tenant_id))
            .outerjoin(TenantUserRole, TenantUserRole.tenant_user_id == TenantUser.id)
            .outerjoin(Role, Role.id == TenantUserRole.role_id)
            .order_by(AppUser.email.asc(), Role.code.asc())
            .all()
        )
        grouped: dict[str, dict] = {}
        for email, status, role_code in rows:
            item = grouped.setdefault(email, {"email": email, "status": status, "role_codes": []})
            if role_code:
                item["role_codes"].append(role_code)
        return [TenantUserOut(**v) for v in grouped.values()]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/tenant-admin/roles", response_model=list[str])
def list_tenant_admin_roles(
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        _ensure_default_tenant_roles(db)
        db.commit()
        rows = (
            db.query(Role.code)
            .filter(Role.scope == "tenant")
            .order_by(Role.code.asc())
            .all()
        )
        return [str(r[0]) for r in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/tenant-admin/tenants", response_model=list[TenantSummaryOut])
def list_accessible_tenant_admin_tenants(
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        tenants = _accessible_tenant_summaries_for_user(db, auth.user_email or "", is_platform_admin)
        return [TenantSummaryOut(id=int(t["id"]), name=str(t["name"]), status=str(t["status"])) for t in tenants]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/tenant-admin/data-hub-connection", response_model=TenantDataHubConnectionOut | None)
def get_tenant_data_hub_connection(
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        row = (
            db.query(TenantDataHubConnection)
            .filter(TenantDataHubConnection.tenant_id == auth.tenant_id)
            .first()
        )
        if not row:
            return None
        return _serialize_tenant_data_hub_connection(row)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.put("/api/admin/tenants/{tenant_id}/data-hub-connection", response_model=TenantDataHubConnectionOut)
def upsert_admin_tenant_data_hub_connection(
    request: Request,
    tenant_id: int,
    payload: TenantDataHubConnectionUpsertRequest,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    values = _validate_data_hub_connection_payload(payload)
    try:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found.")

        row = (
            db.query(TenantDataHubConnection)
            .filter(TenantDataHubConnection.tenant_id == tenant_id)
            .first()
        )
        now = datetime.now(timezone.utc)
        if not row:
            row = TenantDataHubConnection(
                tenant_id=tenant_id,
                created_at=now,
                updated_at=now,
                **values,
            )
            db.add(row)
        else:
            row.base_url = str(values["base_url"])
            row.auth_type = str(values["auth_type"])
            row.auth_header_name = values["auth_header_name"]
            row.auth_secret_ref = values["auth_secret_ref"]
            row.connect_timeout_seconds = int(values["connect_timeout_seconds"])
            row.read_timeout_seconds = int(values["read_timeout_seconds"])
            row.is_active = bool(values["is_active"])
            row.updated_at = now

        tenant.updated_at = now
        db.commit()
        db.refresh(row)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_data_hub_connection_upserted",
            tenant_id=tenant_id,
            entity_type="tenant_data_hub_connection",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={
                "tenant_id": tenant_id,
                "base_url": row.base_url,
                "auth_type": row.auth_type,
                "is_active": bool(row.is_active),
                "connect_timeout_seconds": int(row.connect_timeout_seconds),
                "read_timeout_seconds": int(row.read_timeout_seconds),
            },
        )
        db.commit()
        return _serialize_tenant_data_hub_connection(row)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/admin/tenants/{tenant_id}/data-hub-connection/test")
def test_admin_tenant_data_hub_connection(
    request: Request,
    tenant_id: int,
    auth: AuthContext = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    try:
        row = (
            db.query(TenantDataHubConnection)
            .filter(TenantDataHubConnection.tenant_id == tenant_id)
            .first()
        )
        if not row:
            raise HTTPException(status_code=404, detail="Data Hub connection not found for tenant.")
        status, message = _test_data_hub_connection(row)
        row.last_tested_at = datetime.now(timezone.utc)
        row.last_test_status = status
        row.last_test_message = message
        row.updated_at = datetime.now(timezone.utc)
        db.commit()
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_data_hub_connection_tested",
            tenant_id=tenant_id,
            entity_type="tenant_data_hub_connection",
            entity_id=int(row.id),
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload={"status": status, "message": message},
        )
        db.commit()
        return {
            "tenant_id": tenant_id,
            "status": status,
            "message": message,
            "tested_at": row.last_tested_at.isoformat() if row.last_tested_at else None,
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/entity-search/customer-seed-search")
def entity_search_customer_seed_search(
    tenant_id: int = Query(..., ge=1),
    q: str = Query(..., min_length=1),
    limit: int = Query(default=20, ge=1, le=100),
    business_unit: str | None = Query(default=None),
    customer_segment: str | None = Query(default=None),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Entity Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        return _proxy_data_hub_json(
            connection,
            "/api/graph/customer-seed-search",
            {
                "q": q.strip(),
                "limit": limit,
                "business_unit": (business_unit or "").strip() or None,
                "customer_segment": (customer_segment or "").strip() or None,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/entity-search/customer-graph")
def entity_search_customer_graph(
    tenant_id: int = Query(..., ge=1),
    customer_key: str = Query(..., min_length=1),
    hops: int = Query(default=2, ge=1, le=5),
    max_nodes: int = Query(default=500, ge=10, le=2000),
    max_edges: int = Query(default=2000, ge=10, le=5000),
    include_surrogates: bool = Query(default=True),
    include_ofac_matches: bool = Query(default=True),
    include_txn_flow: bool = Query(default=True),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Entity Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        path = "/api/graph/customer/" + urllib.parse.quote(customer_key.strip(), safe="")
        return _proxy_data_hub_json(
            connection,
            path,
            {
                "hops": hops,
                "max_nodes": max_nodes,
                "max_edges": max_edges,
                "include_surrogates": include_surrogates,
                "include_ofac_matches": include_ofac_matches,
                "include_txn_flow": include_txn_flow,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/entity-search/exposure-seed-search")
def entity_search_exposure_seed_search(
    tenant_id: int = Query(..., ge=1),
    q: str = Query(..., min_length=1),
    limit: int = Query(default=25, ge=1, le=200),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Exposure Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        return _proxy_data_hub_json(
            connection,
            "/api/graph/exposure-seed-search",
            {
                "q": q.strip(),
                "limit": limit,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/entity-search/exposure-graph")
def entity_search_exposure_graph(
    tenant_id: int = Query(..., ge=1),
    node_id: str = Query(..., min_length=1),
    hops: int = Query(default=2, ge=1, le=5),
    max_nodes: int = Query(default=500, ge=10, le=2000),
    max_edges: int = Query(default=2000, ge=10, le=5000),
    include_surrogates: bool = Query(default=True),
    include_ofac_matches: bool = Query(default=True),
    include_txn_flow: bool = Query(default=True),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Exposure Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        return _proxy_data_hub_json(
            connection,
            "/api/graph/exposure",
            {
                "node_id": node_id.strip(),
                "hops": hops,
                "max_nodes": max_nodes,
                "max_edges": max_edges,
                "include_surrogates": include_surrogates,
                "include_ofac_matches": include_ofac_matches,
                "include_txn_flow": include_txn_flow,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/entity-search/exposure-question")
def entity_search_exposure_question(
    payload: ExposureQuestionRequest,
    request: Request,
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            payload.tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Exposure Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, payload.tenant_id)
        question = str(payload.question or "").strip()
        if not question:
            raise HTTPException(status_code=400, detail="question is required.")

        intent_route = _select_exposure_intent_route(question)
        intent_row = intent_route.get("primary_intent") if isinstance(intent_route.get("primary_intent"), dict) else {}
        selected_intent_rows = [
            row
            for row in (intent_route.get("selected_intents") or [])
            if isinstance(row, dict)
        ]
        if not intent_row:
            intent_row = _find_exposure_intent_definition(str(_EXPOSURE_INTENTS_LIBRARY.get("default_intent") or ""))
            selected_intent_rows = [intent_row]
        intent = str(intent_row.get("intent") or "")
        intent_description = str(intent_row.get("description") or "")
        query_plan = _build_exposure_query_plan_from_intent(
            intent_row=intent_row,
            question=question,
            seed_limit=int(payload.seed_limit),
            hops=int(payload.hops),
            max_nodes=int(payload.max_nodes),
            max_edges=int(payload.max_edges),
            include_surrogates=bool(payload.include_surrogates),
            include_ofac_matches=bool(payload.include_ofac_matches),
            include_txn_flow=bool(payload.include_txn_flow),
        )
        query_plan["intent_routing"] = {
            "selected_intents": [str(row.get("intent") or "") for row in selected_intent_rows],
            "routing_mode": str(intent_route.get("routing_mode") or ""),
            "routing_confidence": float(intent_route.get("routing_confidence") or 0.0),
            "routing_rationale": str(intent_route.get("routing_rationale") or ""),
            "rules_top_candidates": intent_route.get("rules_top_candidates") if isinstance(intent_route.get("rules_top_candidates"), list) else [],
        }

        seed_step = _query_plan_step_by_name(query_plan, "seed_search") or {}
        seed_endpoint = str(seed_step.get("endpoint") or "/api/graph/exposure-seed-search")
        seed_params_raw = seed_step.get("params")
        seed_params = seed_params_raw if isinstance(seed_params_raw, dict) else {"q": question, "limit": int(payload.seed_limit)}
        if not str(seed_params.get("q") or "").strip():
            seed_params["q"] = question
        if int(seed_params.get("limit") or 0) < 1:
            seed_params["limit"] = int(payload.seed_limit)

        graph_step = _query_plan_step_by_name(query_plan, "graph_expansion") or {}
        graph_endpoint = str(graph_step.get("endpoint") or "/api/graph/exposure")
        graph_params_template_raw = graph_step.get("params")
        graph_params_template = (
            graph_params_template_raw
            if isinstance(graph_params_template_raw, dict)
            else {
                "hops": int(payload.hops),
                "max_nodes": int(payload.max_nodes),
                "max_edges": int(payload.max_edges),
                "include_surrogates": bool(payload.include_surrogates),
                "include_ofac_matches": bool(payload.include_ofac_matches),
                "include_txn_flow": bool(payload.include_txn_flow),
            }
        )

        queried_data: list[dict[str, object]] = []
        seed_payload = _proxy_data_hub_json(
            connection,
            seed_endpoint,
            seed_params,
        )
        seed_rows_raw = seed_payload.get("results") if isinstance(seed_payload, dict) else []
        seed_rows = seed_rows_raw if isinstance(seed_rows_raw, list) else []
        top_seeds: list[dict[str, object]] = []
        top_seed_count = max(1, min(int(intent_row.get("top_seed_count") or 3), 10))
        for row in seed_rows:
            if isinstance(row, dict):
                top_seeds.append(row)
            if len(top_seeds) >= top_seed_count:
                break
        ordered_seeds = _ordered_seed_candidates(top_seeds)
        graph_seed_candidates = ordered_seeds
        tx_seed_candidates = [
            row
            for row in ordered_seeds
            if str(row.get("node_type") or "") in {"Customer", "Account", "CounterpartyAccount"}
        ] or ordered_seeds

        queried_data.append(
            {
                "step": "seed_search",
                "endpoint": seed_endpoint,
                "params": seed_params,
                "result_count": int(seed_payload.get("result_count") or len(seed_rows)),
                "seed_candidates": [
                    {
                        "node_id": str(row.get("node_id") or ""),
                        "node_type": str(row.get("node_type") or ""),
                        "score": int(row.get("score") or 0),
                    }
                    for row in graph_seed_candidates[:10]
                ],
            }
        )

        evidence: list[dict[str, object]] = []
        aggregate_node_type_counts: dict[str, int] = {}
        aggregate_edge_type_counts: dict[str, int] = {}
        selected_graph_payload: dict[str, object] | None = None
        selected_graph_seed_node_id: str | None = None
        for seed in graph_seed_candidates:
            node_id = str(seed.get("node_id") or "").strip()
            if not node_id:
                continue
            graph_params = dict(graph_params_template)
            graph_params["node_id"] = node_id
            graph_payload = _proxy_data_hub_json(
                connection,
                graph_endpoint,
                graph_params,
            )
            if selected_graph_payload is None:
                selected_graph_payload = graph_payload
                selected_graph_seed_node_id = node_id
            queried_data.append(
                {
                    "step": "graph_expansion",
                    "endpoint": graph_endpoint,
                    "params": graph_params,
                    "result_node_count": int(graph_payload.get("node_count") or 0),
                    "result_edge_count": int(graph_payload.get("edge_count") or 0),
                    "snapshot_id": str(graph_payload.get("snapshot_id") or ""),
                    "as_of_ts": str(graph_payload.get("as_of_ts") or ""),
                }
            )
            graph_summary = _summarize_exposure_graph(seed, graph_payload)
            evidence.append(graph_summary)
            node_counts = graph_summary.get("node_type_counts") if isinstance(graph_summary.get("node_type_counts"), dict) else {}
            edge_counts = graph_summary.get("edge_type_counts") if isinstance(graph_summary.get("edge_type_counts"), dict) else {}
            for k, v in node_counts.items():
                aggregate_node_type_counts[str(k)] = aggregate_node_type_counts.get(str(k), 0) + int(v or 0)
            for k, v in edge_counts.items():
                aggregate_edge_type_counts[str(k)] = aggregate_edge_type_counts.get(str(k), 0) + int(v or 0)


        transaction_evidence: list[dict[str, object]] = []
        tx_step = _query_plan_step_by_name(query_plan, "transaction_details") or {}
        tx_endpoint = str(tx_step.get("endpoint") or "").strip()
        tx_params_template_raw = tx_step.get("params")
        tx_params_template = tx_params_template_raw if isinstance(tx_params_template_raw, dict) else {}
        tx_mapping_info: dict[str, object] | None = None
        interpreted_query: dict[str, object] | None = None
        transaction_linked_node_ids: set[str] = set()
        if tx_endpoint:
            normalized_tx_params_base, tx_mapping_info = _normalize_transaction_filters_for_question(
                connection=connection,
                question=question,
                base_params=tx_params_template,
                filter_overrides=payload.filter_overrides,
            )
            applied_filters_for_clarification = (
                tx_mapping_info.get("applied_filters")
                if isinstance(tx_mapping_info, dict) and isinstance(tx_mapping_info.get("applied_filters"), dict)
                else {}
            )
            clarification = (
                None
                if isinstance(payload.filter_overrides, dict) and payload.filter_overrides
                else _outside_us_clarification(question, applied_filters_for_clarification)
            )
            interpreted_query = _build_interpreted_query(
                question=question,
                selected_intents=selected_intent_rows,
                seed_candidates=ordered_seeds,
                tx_mapping_info=tx_mapping_info,
                clarification=clarification,
            )
            queried_data.append(
                {
                    "step": "transaction_filter_mapping",
                    "endpoint": "/api/graph/transaction-filter-catalog",
                    "mapping": tx_mapping_info,
                }
            )
            if clarification:
                return {
                    "question": question,
                    "intent": intent,
                    "intent_description": intent_description,
                    "intents": [str(row.get("intent") or "") for row in selected_intent_rows],
                    "intent_routing": query_plan.get("intent_routing"),
                    "structured_query_plan": query_plan,
                    "queried_data": queried_data,
                    "mode": "needs_clarification",
                    "status": "needs_clarification",
                    "summary": str(clarification.get("question") or ""),
                    "relevance_explanation": [str(clarification.get("reason") or "")],
                    "relationship_findings": {
                        "aggregate_node_type_counts": aggregate_node_type_counts,
                        "aggregate_edge_type_counts": aggregate_edge_type_counts,
                    },
                    "evidence": evidence,
                    "graph_payload": selected_graph_payload if bool(payload.include_graph) else None,
                    "graph_seed_node_id": selected_graph_seed_node_id,
                    "transaction_evidence": [],
                    "transaction_filter_mapping": tx_mapping_info,
                    "interpreted_query": interpreted_query,
                    "clarification": clarification,
                    "enriched_transaction_nodes": [],
                    "seed_selection": {
                        "graph_seed_candidates": [str(row.get("node_id") or "") for row in graph_seed_candidates[:10]],
                        "transaction_seed_candidates": [str(row.get("node_id") or "") for row in tx_seed_candidates[:10]],
                    },
                    "assumptions": [
                        "Execution paused because the geographic filter is ambiguous.",
                    ],
                    "limitations": [
                        "Choose a dimension for the outside-US filter and rerun the question with that clarification.",
                    ],
                    "audit_trail": {
                        "module_code": "entity_search",
                        "action": "exposure_question_needs_clarification",
                        "recorded_at": datetime.now(timezone.utc).isoformat(),
                    },
                }
            for seed in tx_seed_candidates[:4]:
                node_id = str(seed.get("node_id") or "").strip()
                if not node_id:
                    continue
                tx_params = dict(normalized_tx_params_base)
                tx_params["node_id"] = node_id
                if int(tx_params.get("hops") or 0) < 1:
                    tx_params["hops"] = int(payload.hops)
                if int(tx_params.get("limit") or 0) < 1:
                    tx_params["limit"] = 200
                tx_payload = _proxy_data_hub_json(
                    connection,
                    tx_endpoint,
                    tx_params,
                )
                tx_rows = tx_payload.get("rows") if isinstance(tx_payload.get("rows"), list) else []
                transaction_linked_node_ids.update(
                    _transaction_node_ids_from_rows([r for r in tx_rows if isinstance(r, dict)])
                )
                queried_data.append(
                    {
                        "step": "transaction_details",
                        "endpoint": tx_endpoint,
                        "params": tx_params,
                        "result_row_count": int(tx_payload.get("row_count") or 0),
                    }
                )
                transaction_evidence.append(
                    {
                        "seed_node_id": node_id,
                        "row_count": int(tx_payload.get("row_count") or 0),
                        "summary": tx_payload.get("summary") if isinstance(tx_payload.get("summary"), dict) else {},
                        "sample_rows": tx_rows[:25] if isinstance(tx_rows, list) else [],
                        "filter_mapping": tx_mapping_info,
                    }
                )

        if interpreted_query is None:
            interpreted_query = _build_interpreted_query(
                question=question,
                selected_intents=selected_intent_rows,
                seed_candidates=ordered_seeds,
                tx_mapping_info=tx_mapping_info,
            )

        enriched_transaction_nodes: list[str] = []
        if bool(payload.include_graph) and selected_graph_payload and transaction_linked_node_ids:
            selected_elements = (
                selected_graph_payload.get("elements")
                if isinstance(selected_graph_payload.get("elements"), dict)
                else {}
            )
            selected_nodes = selected_elements.get("nodes") if isinstance(selected_elements.get("nodes"), list) else []
            existing_node_ids = {
                str((n.get("data", {}) or {}).get("id") or "")
                for n in selected_nodes
                if isinstance(n, dict)
            }
            candidate_node_ids = sorted(
                [nid for nid in transaction_linked_node_ids if nid and nid not in existing_node_ids]
            )[:8]
            for tx_node_id in candidate_node_ids:
                enrich_params = dict(graph_params_template)
                enrich_params["node_id"] = tx_node_id
                enrich_params["hops"] = min(int(payload.hops), 2)
                enrich_params["max_nodes"] = min(int(payload.max_nodes), 350)
                enrich_params["max_edges"] = min(int(payload.max_edges), 1200)
                enrich_payload = _proxy_data_hub_json(
                    connection,
                    graph_endpoint,
                    enrich_params,
                )
                selected_graph_payload = _merge_graph_payloads(selected_graph_payload, enrich_payload)
                enriched_transaction_nodes.append(tx_node_id)

                node_type, business_key = _parse_node_id(tx_node_id)
                tx_seed = {
                    "node_id": tx_node_id,
                    "node_type": node_type,
                    "business_key": business_key,
                    "label": tx_node_id,
                }
                tx_graph_summary = _summarize_exposure_graph(tx_seed, enrich_payload)
                evidence.append(tx_graph_summary)
                node_counts = tx_graph_summary.get("node_type_counts") if isinstance(tx_graph_summary.get("node_type_counts"), dict) else {}
                edge_counts = tx_graph_summary.get("edge_type_counts") if isinstance(tx_graph_summary.get("edge_type_counts"), dict) else {}
                for k, v in node_counts.items():
                    aggregate_node_type_counts[str(k)] = aggregate_node_type_counts.get(str(k), 0) + int(v or 0)
                for k, v in edge_counts.items():
                    aggregate_edge_type_counts[str(k)] = aggregate_edge_type_counts.get(str(k), 0) + int(v or 0)

                queried_data.append(
                    {
                        "step": "transaction_node_graph_enrichment",
                        "endpoint": graph_endpoint,
                        "params": enrich_params,
                        "result_node_count": int(enrich_payload.get("node_count") or 0),
                        "result_edge_count": int(enrich_payload.get("edge_count") or 0),
                    }
                )

        deterministic_summary, deterministic_findings = _deterministic_exposure_summary(question, intent, evidence)
        assumptions = _merge_unique_strings(
            [
                str(v)
                for row in selected_intent_rows
                for v in (row.get("assumptions") or [])
                if str(v).strip()
            ]
        )
        if not assumptions:
            assumptions = [
                "Results are constrained to the tenant's configured Data Hub connection and active snapshot content.",
                "Seed matching is lexical and may miss semantically related names not present in matched fields.",
                "Graph scope is limited by hops/max_nodes/max_edges controls.",
            ]
        limitations = _merge_unique_strings(
            [
                str(v)
                for row in selected_intent_rows
                for v in (row.get("limitations") or [])
                if str(v).strip()
            ]
        )
        if not limitations:
            limitations = [
                "No external data sources were queried beyond the configured Data Hub APIs.",
                "Absence of a relationship in this response is not evidence of true absence in all systems.",
            ]

        llm_result = _openai_exposure_grounded_summary(
            question=question,
            intent=intent,
            intent_description=intent_description,
            query_plan=query_plan,
            evidence=evidence,
        )
        mode = "deterministic"
        final_summary = deterministic_summary
        relevance_explanation = deterministic_findings
        if llm_result:
            mode = "grounded_openai"
            final_summary = str(llm_result.get("summary") or deterministic_summary)
            why_relevant = str(llm_result.get("why_relevant") or "").strip()
            relevance_explanation = ([why_relevant] if why_relevant else []) + deterministic_findings
            llm_assumptions = llm_result.get("assumptions") if isinstance(llm_result.get("assumptions"), list) else []
            llm_limitations = llm_result.get("limitations") if isinstance(llm_result.get("limitations"), list) else []
            assumptions = [str(v) for v in llm_assumptions if str(v).strip()] or assumptions
            limitations = [str(v) for v in llm_limitations if str(v).strip()] or limitations

        audit_payload = {
            "tenant_id": int(payload.tenant_id),
            "question": question,
            "intent": intent,
            "mode": mode,
            "query_plan": query_plan,
            "queried_data": queried_data,
            "evidence_count": len(evidence),
            "intent_library_version": str(_EXPOSURE_INTENTS_LIBRARY.get("library_version") or ""),
            "intent_routing": query_plan.get("intent_routing"),
            "transaction_filter_mapping": tx_mapping_info,
            "interpreted_query": interpreted_query,
            "enriched_transaction_nodes": enriched_transaction_nodes,
            "seed_selection": {
                "graph_seed_candidates": [str(row.get("node_id") or "") for row in graph_seed_candidates[:10]],
                "transaction_seed_candidates": [str(row.get("node_id") or "") for row in tx_seed_candidates[:10]],
            },
            "top_seed_node_ids": [str((row.get("seed") or {}).get("node_id") or "") for row in evidence if isinstance(row, dict)],
        }
        _record_audit_event(
            db,
            module_code="entity_search",
            action="exposure_question_answered",
            tenant_id=int(payload.tenant_id),
            entity_type="exposure_question",
            entity_id=None,
            actor_user_id=_get_user_id_by_email(db, auth.user_email or ""),
            actor_email=auth.user_email,
            request=request,
            payload=audit_payload,
        )
        db.commit()

        return {
            "question": question,
            "intent": intent,
            "intent_description": intent_description,
            "intents": [str(row.get("intent") or "") for row in selected_intent_rows],
            "intent_routing": query_plan.get("intent_routing"),
            "structured_query_plan": query_plan,
            "queried_data": queried_data,
            "mode": mode,
            "summary": final_summary,
            "relevance_explanation": relevance_explanation,
            "relationship_findings": {
                "aggregate_node_type_counts": aggregate_node_type_counts,
                "aggregate_edge_type_counts": aggregate_edge_type_counts,
            },
            "evidence": evidence,
            "graph_payload": selected_graph_payload if bool(payload.include_graph) else None,
            "graph_seed_node_id": selected_graph_seed_node_id,
            "transaction_evidence": transaction_evidence,
            "transaction_filter_mapping": tx_mapping_info,
            "interpreted_query": interpreted_query,
            "enriched_transaction_nodes": enriched_transaction_nodes,
            "seed_selection": {
                "graph_seed_candidates": [str(row.get("node_id") or "") for row in graph_seed_candidates[:10]],
                "transaction_seed_candidates": [str(row.get("node_id") or "") for row in tx_seed_candidates[:10]],
            },
            "assumptions": assumptions,
            "limitations": limitations,
            "audit_trail": {
                "module_code": "entity_search",
                "action": "exposure_question_answered",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            },
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.get("/api/entity-search/node-neighbors")
def entity_search_node_neighbors(
    tenant_id: int = Query(..., ge=1),
    node_id: str = Query(..., min_length=1),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    exclude_node_ids: str | None = Query(default=None),
    include_surrogates: bool = Query(default=True),
    include_ofac_matches: bool = Query(default=True),
    include_txn_flow: bool = Query(default=True),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Entity Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        return _proxy_data_hub_json(
            connection,
            "/api/graph/node-neighbors",
            {
                "node_id": node_id.strip(),
                "limit": limit,
                "offset": offset,
                "exclude_node_ids": (exclude_node_ids or "").strip() or None,
                "include_surrogates": include_surrogates,
                "include_ofac_matches": include_ofac_matches,
                "include_txn_flow": include_txn_flow,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")




@app.get("/api/entity-search/exposure-transactions")
def entity_search_exposure_transactions(
    tenant_id: int = Query(..., ge=1),
    node_id: str = Query(..., min_length=1),
    hops: int = Query(default=2, ge=1, le=5),
    limit: int = Query(default=500, ge=1, le=10000),
    outside_country_code_2: str | None = Query(default=None),
    outside_counterparty_jurisdiction: str | None = Query(default=None),
    counterparty_jurisdiction: str | None = Query(default=None),
    outside_customer_country_code: str | None = Query(default=None),
    customer_country_code: str | None = Query(default=None),
    outside_branch_country_code: str | None = Query(default=None),
    branch_country_code: str | None = Query(default=None),
    account_type_contains: str | None = Query(default=None),
    account_name_contains: str | None = Query(default=None),
    customer_segment_contains: str | None = Query(default=None),
    customer_business_unit: str | None = Query(default=None),
    branch_type_contains: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    aml_classification_contains: str | None = Query(default=None),
    mechanism_contains: str | None = Query(default=None),
    include_surrogates: bool = Query(default=True),
    include_ofac_matches: bool = Query(default=True),
    include_txn_flow: bool = Query(default=True),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Exposure Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        return _proxy_data_hub_json(
            connection,
            "/api/graph/exposure/transactions",
            {
                "node_id": node_id.strip(),
                "hops": hops,
                "limit": limit,
                "outside_country_code_2": (outside_country_code_2 or "").strip() or None,
                "outside_counterparty_jurisdiction": (outside_counterparty_jurisdiction or "").strip() or None,
                "counterparty_jurisdiction": (counterparty_jurisdiction or "").strip() or None,
                "outside_customer_country_code": (outside_customer_country_code or "").strip() or None,
                "customer_country_code": (customer_country_code or "").strip() or None,
                "outside_branch_country_code": (outside_branch_country_code or "").strip() or None,
                "branch_country_code": (branch_country_code or "").strip() or None,
                "account_type_contains": (account_type_contains or "").strip() or None,
                "account_name_contains": (account_name_contains or "").strip() or None,
                "customer_segment_contains": (customer_segment_contains or "").strip() or None,
                "customer_business_unit": (customer_business_unit or "").strip() or None,
                "branch_type_contains": (branch_type_contains or "").strip() or None,
                "direction": (direction or "").strip() or None,
                "aml_classification_contains": (aml_classification_contains or "").strip() or None,
                "mechanism_contains": (mechanism_contains or "").strip() or None,
                "include_surrogates": include_surrogates,
                "include_ofac_matches": include_ofac_matches,
                "include_txn_flow": include_txn_flow,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")

@app.get("/api/entity-search/customer-transactions")
def entity_search_customer_transactions(
    tenant_id: int = Query(..., ge=1),
    customer_key: str = Query(..., min_length=1),
    limit: int = Query(default=5000, ge=1, le=50000),
    auth: AuthContext = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        is_platform_admin = _is_platform_admin_user(db, auth.user_email)
        allowed = is_platform_admin or _user_has_any_tenant_role(
            db,
            auth.user_email,
            tenant_id,
            ("tenant_investigator", "tenant_admin"),
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Entity Search requires tenant_investigator or tenant_admin.")

        connection = _resolve_tenant_data_hub_connection_or_404(db, tenant_id)
        path = "/api/graph/customer/" + urllib.parse.quote(customer_key.strip(), safe="") + "/transactions"
        return _proxy_data_hub_json(
            connection,
            path,
            {
                "limit": limit,
            },
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.post("/api/tenant-admin/users", response_model=TenantUserOut)
def upsert_tenant_user(
    request: Request,
    payload: TenantUserUpsertRequest,
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    email = payload.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="email is required.")
    if payload.status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="status must be active|inactive.")

    try:
        app_user = db.query(AppUser).filter(AppUser.email == email).first()
        invite_url = None
        invite_expires_at = None
        if not app_user:
            app_user = AppUser(email=email, status="active", created_at=datetime.now(timezone.utc))
            db.add(app_user)
            db.flush()

        tenant_user = (
            db.query(TenantUser)
            .filter(TenantUser.tenant_id == auth.tenant_id, TenantUser.app_user_id == app_user.id)
            .first()
        )
        if not tenant_user:
            tenant_user = TenantUser(
                tenant_id=auth.tenant_id,
                app_user_id=app_user.id,
                status=payload.status,
                created_at=datetime.now(timezone.utc),
            )
            db.add(tenant_user)
            db.flush()
        else:
            tenant_user.status = payload.status

        role_map = _ensure_role_rows(db, payload.role_codes)
        db.query(TenantUserRole).filter(TenantUserRole.tenant_user_id == tenant_user.id).delete()
        for code in sorted(role_map.keys()):
            db.add(TenantUserRole(tenant_user_id=tenant_user.id, role_id=role_map[code]))

        if not app_user.password_hash:
            invite_token, expires_at = _issue_password_setup_invite(app_user)
            invite_url = _build_password_setup_url(invite_token)
            invite_expires_at = expires_at.isoformat()

        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_user_upserted",
            tenant_id=auth.tenant_id,
            entity_type="tenant_user",
            entity_id=int(tenant_user.id),
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"email": email, "status": tenant_user.status, "roles": sorted(role_map.keys())},
        )
        db.commit()
        return TenantUserOut(
            email=email,
            status=tenant_user.status,
            role_codes=sorted(role_map.keys()),
            invite_url=invite_url,
            invite_expires_at=invite_expires_at,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")


@app.delete("/api/tenant-admin/users/{email}")
def remove_tenant_user(
    request: Request,
    email: str,
    auth: AuthContext = Depends(require_tenant_admin_or_platform_admin),
    db: Session = Depends(get_db),
):
    normalized = email.strip().lower()
    if not normalized:
        raise HTTPException(status_code=400, detail="email is required.")
    try:
        app_user = db.query(AppUser).filter(AppUser.email == normalized).first()
        if not app_user:
            return {"success": True, "removed": False}

        tenant_user = (
            db.query(TenantUser)
            .filter(TenantUser.tenant_id == auth.tenant_id, TenantUser.app_user_id == app_user.id)
            .first()
        )
        if not tenant_user:
            return {"success": True, "removed": False}

        actor_user_id = _get_user_id_by_email(db, auth.user_email or "")
        removed_tenant_user_id = int(tenant_user.id)
        db.query(TenantUserRole).filter(TenantUserRole.tenant_user_id == tenant_user.id).delete()
        db.delete(tenant_user)
        _record_audit_event(
            db,
            module_code="tenant_admin",
            action="tenant_user_removed",
            tenant_id=auth.tenant_id,
            entity_type="tenant_user",
            entity_id=removed_tenant_user_id,
            actor_user_id=actor_user_id,
            actor_email=auth.user_email,
            request=request,
            payload={"email": normalized},
        )
        db.commit()
        return {"success": True, "removed": True}
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")
