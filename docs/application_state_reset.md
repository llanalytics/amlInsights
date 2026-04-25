# AML Platform State Reset

Last updated: 2026-04-24

## Purpose

Use this document to quickly re-establish context across the three active repos:

- `amlInsights` (platform app and tenant-facing UI)
- `amlredflags` (red-flag ingestion and scoring service)
- `amlInsightsDataHub` (data ingestion/data quality/graph-ready data hub)

This is intended to be the "where we left off" checkpoint.

## Workspace Snapshot

- Repos scanned:
  - `/home/ehale/Documents/amlInsights`
  - `/home/ehale/Documents/amlredflags`
  - `/home/ehale/Documents/amlInsightsDataHub`
- Git status on 2026-04-24:
  - All three repos are on `main`
  - All three repos are clean (no uncommitted changes)

## 1) amlInsights

Repo: `/home/ehale/Documents/amlInsights`

### Background

- FastAPI app deployed on Heroku with SQLAlchemy + Alembic.
- Provides platform and tenant UI surfaces (dashboard, entity/exposure search, tenant admin, workflow/red-flag curation).
- Includes local and remote migration scripts and admin bootstrap scripts.
- Supports shared database patterns with `amlredflags`.

### Recent updates

- `2026-04-23` (`e0db8f0`, message: `updates`)
  - Added tenant data hub connection migration:
    - `alembic/versions/20260421_0018_add_tenant_data_hub_connections.py`
  - Updated core app/platform logic:
    - `main.py`, `platform_models.py`, `platform_schemas.py`
  - Updated key UI screens:
    - `templates/dashboard.html`
    - `templates/entity_search.html`
    - `templates/exposure_search.html`
    - `templates/components/customer_screen.html`
    - `templates/tenant_admin.html`
  - Role seed adjustments:
    - `install/roles.csv`
- `2026-04-17` to `2026-04-18`
  - Security and repo hygiene updates focused on `.env` handling via `.gitignore`.
  - Large platform evolution commit (`35f11de`) touching:
    - auth/platform models and schemas
    - tenant/workflow/red-flag migrations
    - setup/migration scripts
    - multiple docs and UI templates

## 2) amlredflags

Repo: `/home/ehale/Documents/amlredflags`

### Background

- Clean-slate AML red flags service (`amlredflags-v2`) built with FastAPI.
- Owns red flag ingestion/batch orchestration and catalog endpoints.
- Uses SQLAlchemy + Alembic with PostgreSQL/Heroku.
- Supports schema isolation and shared-database deployment with `amlInsights`.

### Recent updates

- `2026-04-18` (`3baab50`, message: `small`)
  - `.gitignore` hygiene update.
- `2026-04-17` (`b21c6ec`, message: `lots of updates`)
  - Expanded migration history and data model:
    - core tables
    - batch failure reason
    - platform workflow tables
    - tenant workflow linkage
    - red flag tag/raw prediction columns
  - Updated service logic and API schema layers:
    - `app/analyzer.py`
    - `app/batch.py`
    - `app/config.py`
    - `app/main.py`
    - `app/models.py`
    - `app/schemas.py`
    - `app/synonyms.py`
- `2026-04-05` to `2026-04-11`
  - Added health-check scripts and batch behavior updates (article pull/store path).

## 3) amlInsightsDataHub

Repo: `/home/ehale/Documents/amlInsightsDataHub`

### Background

- Standalone AML data ingestion and management app.
- Implements landing-file ingestion, DQ rules, referential integrity checks, and job stats tracking.
- Maintains star-schema style dimensions/bridges/fact tables with SCD-style behavior.
- Provides monitoring APIs and graph endpoints for entity/relationship analysis.
- Uses Alembic migrations and scripted sample-data refresh flows (ISO/OFAC/Panama).

### Recent updates

- `2026-04-23` (`ab0e911`, message: `updates`)
  - Added branch dimension and fact link support:
    - `alembic/versions/20260420_0010_add_dh_dim_branch.py`
    - `alembic/versions/20260420_0011_add_branch_key_to_dh_fact_cash.py`
  - Graph and pipeline changes:
    - `app/graph_layer.py`
    - `app/main.py`
    - `app/models.py`
    - `app/pipeline.py`
  - Updated README and sample/config artifacts.
- `2026-04-19` (`134b39d`, message: `ff`)
  - Added Panama reference tables and cash-fact column changes:
    - `20260418_0007_add_panama_reference_tables.py`
    - `20260418_0008_add_secondary_account_key_to_dh_fact_cash.py`
    - `20260419_0009_rename_dh_fact_cash_country_code_to_country_code_2.py`
- `2026-04-18` (`c3e5980`, message: `add country, currency and sdn`)
  - Added/updated country, currency, SDN data support:
    - customer business unit addition
    - country key rename to `country_code_2`
    - new OFAC SDN dimension
    - corresponding model/pipeline/schema updates

## Suggested "Start Here" Flow Next Session

1. Read this file first.
2. Open each repo README for run/migrate commands and env expectations.
3. Verify DB target (local shared DB vs remote/Postgres) before running migrations.
4. Run migrations in dependency order for planned work area.
5. Capture any new decisions back into this file under a new dated section.

## Session Updates

### 2026-04-24 - Exposure Interface Refactor (LLM-Grounded Pattern, Phase 1)

- Goal:
  - Begin reworking Exposure Search to follow explainable AML governance pattern:
    - natural language question
    - intent detection
    - structured query plan
    - data retrieval execution
    - grounded summary
    - audit trail
- Backend changes in `amlInsights`:
  - Added request model:
    - `ExposureQuestionRequest` in `main.py`
  - Added new API endpoint:
    - `POST /api/entity-search/exposure-question`
  - Implemented new flow in endpoint:
    - Role/tenant authorization check
    - Intent detection (`sanctions_exposure`, `offshore_exposure`, `transaction_exposure`, `counterparty_exposure`, `general_exposure`)
    - Query plan construction
    - Data Hub execution via:
      - `/api/graph/exposure-seed-search`
      - `/api/graph/exposure` (top seeds)
    - Evidence extraction from graph payloads (node/edge counts, key entities, key relationship edges)
    - Grounded summary generation:
      - deterministic fallback
      - optional OpenAI constrained synthesis (`OPENAI_EXPOSURE_ASSISTANT_ENABLED`)
    - Audit logging using existing `ops_audit_events` path via `_record_audit_event` action:
      - `exposure_question_answered`
- UI changes in `amlInsights`:
  - Updated `templates/exposure_search.html` with new "Grounded Exposure Assistant" panel.
  - Added question-driven workflow controls and output sections:
    - intent + mode
    - summary + relevance reasoning
    - queried data
    - structured query plan
    - relationship findings
    - assumptions + limitations
    - audit trail
    - evidence table for top seeds
- Validation:
  - `python3 -m py_compile /home/ehale/Documents/amlInsights/main.py` succeeded.
- Next suggested step:
  - Add explicit "evidence citation IDs" (edge/node references) and a saved investigation artifact export so analysts can attach results to case files.

### 2026-04-24 - Intent Library Implementation (Phase 2)

- Goal:
  - Replace hardcoded exposure intent detection and query-plan construction with a managed, versioned intent library.
- Added config-driven library:
  - New file:
    - `/home/ehale/Documents/amlInsights/config/exposure_intents.json`
  - Includes:
    - `library_version`
    - `default_intent`
    - Intent entries with:
      - `intent`, `description`, `priority`
      - `patterns`, `synonyms`
      - `top_seed_count`
      - `assumptions`, `limitations`
      - `query_plan_template` (step/endpoint/param templates)
- Backend refactor in `main.py`:
  - Added library loading + validation at startup/import time.
  - Added intent scoring/selection against question text.
  - Added query-plan template rendering with runtime placeholders.
  - Refactored `POST /api/entity-search/exposure-question` to:
    - choose intent from library
    - build query plan from template
    - execute seed/graph retrieval using template endpoints/params
    - use intent-specific assumptions/limitations
    - include intent library version in audit payload
- Validation:
  - `python3 -m py_compile /home/ehale/Documents/amlInsights/main.py` succeeded.
  - JSON config parse sanity check succeeded (`6` intents loaded, default `general_exposure`).
- How to extend:
  - Add/adjust intents directly in `config/exposure_intents.json` without changing endpoint logic.

### 2026-04-24 - Intent Routing Layer (Phase 3)

- Goal:
  - Add a routing layer that maps a question to one or multiple intents.
  - When rule confidence is low, invoke OpenAI for intent-routing assistance before falling back to `general_exposure`.
- Backend updates in `amlInsights/main.py`:
  - Added confidence-aware routing orchestration:
    - rules scoring across intent library
    - multi-intent selection when secondary intents are close to primary score
    - normalized routing confidence metric
  - Added OpenAI-assisted intent router path (low-confidence escalation):
    - `_openai_assist_exposure_intent_mapping(...)`
    - constrained to configured intent catalog
    - returns `intent_codes`, `confidence`, `rationale`
  - Added env controls:
    - `OPENAI_EXPOSURE_INTENT_ROUTER_ENABLED`
    - `OPENAI_EXPOSURE_INTENT_ROUTER_TIMEOUT_SECONDS`
    - `EXPOSURE_INTENT_ROUTE_CONFIDENCE_THRESHOLD`
  - Updated `/api/entity-search/exposure-question` response/audit payload to include:
    - selected intent list
    - routing mode
    - routing confidence
    - routing rationale/candidate trace
- UI update:
  - Exposure assistant intent display now shows intent combination + routing mode/confidence.
- Validation:
  - `python3 -m py_compile /home/ehale/Documents/amlInsights/main.py` succeeded.

### 2026-04-24 - Cash Fact Transaction Detail Extension (Phase 4)

- Added Data Hub endpoint `GET /api/graph/exposure/transactions` to retrieve transaction detail rows from `dh_fact_cash` for exposure seed neighborhoods.
- Added amlInsights proxy endpoint `GET /api/entity-search/exposure-transactions`.
- Exposure question flow now captures `transaction_evidence` for relevant intents using wire/outbound/outside-US filters.
- Added `negative_news_exposure` intent and aligned Panama nexus language to potential negative-news signals.
- Updated Exposure UI to show transaction evidence summary rows.
- Refined transaction filtering to support `mechanism_contains` (for example `wire`) in addition to AML classification, to match transaction types where classification is `External Funds Transfer` and mechanism is `Wire`.

### 2026-04-24 - Real-Time Filter Mapping (Phase 5)

- Added Data Hub endpoint:
  - `GET /api/graph/transaction-filter-catalog`
  - Returns live filter vocabulary from current Data Hub content (`directions`, `mechanisms`, AML classifications, country codes).
- Added hybrid transaction filter normalization in `amlInsights` exposure flow:
  - Deterministic synonym mapping first (for terms like `payments`, `transfers`, `wire`).
  - Constrained OpenAI mapping fallback when deterministic confidence is low.
  - Output is validated against live catalog values before execution.
- Added mapping telemetry to response/audit:
  - `transaction_filter_mapping` includes mode, confidence, rationale, and applied filters.
- New env toggles:
  - `OPENAI_EXPOSURE_FILTER_MAPPER_ENABLED`
  - `OPENAI_EXPOSURE_FILTER_MAPPER_TIMEOUT_SECONDS`
  - `EXPOSURE_FILTER_MAPPER_CONFIDENCE_THRESHOLD`

### 2026-04-24 - Assistant Graph Inline Return (Phase 6)

- `POST /api/entity-search/exposure-question` now supports `include_graph` and returns:
  - `graph_payload` (existing graph JSON shape from exposure graph retrieval)
  - `graph_seed_node_id`
- Exposure UI `Analyze Question` now uses returned `graph_payload` to render the existing Exposure Graph section directly, so question analysis and graph visualization stay in one flow.

### 2026-04-24 - Transaction Node Graph Enrichment (Phase 7)

- Tightened interaction between transaction extension and graph exposure:
  - Transaction detail rows now produce linked node IDs (`Account:*`, `CounterpartyAccount:*`).
  - Exposure assistant expands graph for transaction-linked nodes that are not already present.
  - Expanded subgraphs are merged into returned `graph_payload` for visualization.
  - Negative-news signal evidence (for example Panama/OFAC-linked relationships) is now collected from these transaction-linked node expansions as part of the same assistant run.
- New response/audit detail:
  - `enriched_transaction_nodes`
  - additional `transaction_node_graph_enrichment` query steps in `queried_data`.

### 2026-04-24 - Seed Prioritization Tightening (Phase 8)

- Addressed issue where exposure graph could center on Panama-heavy neighborhoods while transaction nodes stayed underrepresented.
- Added seed ordering and dual candidate sets in exposure assistant:
  - Graph seeds now prioritized by node type (`Customer`, `Account`, `CounterpartyAccount` first; Panama/OFAC later).
  - Transaction detail seeds now explicitly prefer transaction-capable node types.
- Added seed debug trace in response/audit:
  - `seed_selection.graph_seed_candidates`
  - `seed_selection.transaction_seed_candidates`
- Goal: ensure transactional expansion contributes visible account/counterparty nodes and associated negative-news overlays in the same graph run.
