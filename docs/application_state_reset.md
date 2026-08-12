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

### 2026-04-27 - Exposure Investigation Sessions (Phase 9)

- Confirmed the previous checkpoint:
  - `Show exposure for ARIGATO LIMITED outside the US` returns `needs_clarification`.
  - Clarification choices include:
    - Counterparty jurisdiction
    - Transaction country
    - Customer country
    - Branch country
  - Rerunning with `outside_counterparty_jurisdiction=US` interprets as:
    - `counterparty.jurisdiction outside US`
  - Transaction evidence returned 15 rows and sampled jurisdictions excluded `US`.
- Added persisted exposure investigation session support in `amlInsights`:
  - New migration:
    - `alembic/versions/20260427_0019_add_exposure_sessions.py`
  - New tables:
    - `exp_sessions`
    - `exp_session_messages`
    - `exp_session_interpretations`
  - New ORM models:
    - `ExposureSession`
    - `ExposureSessionMessage`
    - `ExposureSessionInterpretation`
- Added Exposure Search APIs:
  - `GET /api/entity-search/exposure-sessions`
  - `POST /api/entity-search/exposure-sessions`
  - `GET /api/entity-search/exposure-sessions/{session_id}`
  - `PATCH /api/entity-search/exposure-sessions/{session_id}`
  - `POST /api/entity-search/exposure-question` now accepts optional `session_id` and persists:
    - user question message
    - assistant summary message
    - interpretation/query/filter/response snapshot
- UI changes:
  - `templates/exposure_search.html` now has a lightweight Investigation Session panel.
  - `Analyze Question` auto-creates a session when needed and sends `session_id` with analysis calls.
  - Clarification reruns remain attached to the active session.
- Validation:
  - `python -m py_compile main.py platform_models.py` succeeded.
  - `./scripts/migrate_db.sh local` upgraded local DB to `20260427_0019`.
  - Created session `#1` locally and verified:
    - 2 persisted messages
    - 1 persisted interpretation
    - stored filter snapshot includes `outside_counterparty_jurisdiction = US`.
- Next recommended step:
  - Add true follow-up interpretation that uses session history to carry forward prior subject/filter context for prompts like:
    - `Now only show wires`
    - `Switch outside US to transaction country instead`
    - `Limit to Panama-linked counterparties`

### 2026-04-27 - Session-Aware Exposure Follow-Ups (Phase 10)

- Added follow-up context resolution for `POST /api/entity-search/exposure-question` when `session_id` is present.
- Behavior:
  - Loads the latest persisted interpretation for the session.
  - Carries forward prior subject when the analyst asks a short follow-up.
  - Carries forward prior structured transaction filters.
  - Lets explicit follow-up language override dimensions, for example:
    - `Switch outside US to transaction country instead`
  - Adds `followup_resolution` to response/audit/session snapshot, including:
    - `original_question`
    - `effective_question`
    - prior subject/filter context
    - inherited filter overrides
- Added guardrail:
  - When structured overrides are inherited or supplied, the OpenAI transaction filter mapper no longer adds extra filters that can over-constrain transaction evidence.
- Added transaction-context bridge:
  - If a follow-up selects an intent without a transaction detail step, but the prior session had transaction filters, a `transaction_details` step is added to the query plan.
  - This keeps prompts like `Limit to Panama-linked counterparties` from dropping the prior outbound/wire/non-US transaction context.
- Verification completed locally:
  - Baseline:
    - `Show exposure for ARIGATO LIMITED outside the US` with counterparty-jurisdiction clarification returned 15 transaction rows.
  - Follow-up:
    - `Now only show wires`
    - Effective question: `Now only show wires for ARIGATO LIMITED`
    - Carried forward outbound + wire + counterparty jurisdiction outside US.
    - Returned 15 transaction rows.
  - Follow-up:
    - `Switch outside US to transaction country instead`
    - Effective question: `Switch outside US to transaction country instead for ARIGATO LIMITED`
    - Switched to `outside_country_code_2 = US`.
    - Returned 17 transaction rows.
  - Follow-up:
    - `Limit to Panama-linked counterparties`
    - Effective question: `Limit to Panama-linked counterparties for ARIGATO LIMITED`
    - Selected `offshore_exposure`.
    - Added transaction detail step from prior context.
    - Returned 15 transaction rows.
- Next recommended step:
  - Add a visible session transcript/history panel in Exposure Search so analysts can review and reload prior session turns from the browser.

### 2026-04-27 - Exposure Session Transcript UI (Phase 11)

- Added a lightweight session history panel to `templates/exposure_search.html`.
- New UI elements:
  - Recent Sessions list:
    - loads the latest exposure sessions for the current tenant
    - supports manual refresh
    - supports loading an older session as the active session
  - Active Transcript:
    - shows persisted user/assistant turns
    - shows the interpreted natural-language summary for turns with interpretations
    - includes `Restore` and `Rerun` actions for persisted interpretation turns
- Behavior:
  - Starting a new analysis still auto-creates a session when none is active.
  - Completed analyses refresh the active transcript and recent session list.
  - `Restore` renders the saved response snapshot back into the analysis pane.
  - `Rerun` uses the saved original analyst question when available, preserving follow-up behavior through the current active session.
- Validation:
  - `python -m py_compile main.py platform_models.py` succeeded.
  - Session list API returned existing local sessions.
  - Session detail API for local session `#4` returned:
    - 4 messages
    - 2 interpretations
    - latest original question: `Limit to Panama-linked counterparties`
    - latest effective question: `Limit to Panama-linked counterparties for ARIGATO LIMITED`
- Note:
  - Direct `/ui/exposure-search` curl redirects to `/login` without a browser session, as expected. The page still uses session auth for browser rendering while API calls use the existing `x-user-email` local/test path.
- Next recommended step:
  - Add a small session title/status editor and optional archive action so old investigations can be closed without leaving the page.

### 2026-04-27 - Subjectless Transaction Aggregate Fix (France Wires)

- Issue found:
  - Question:
    - `how many wires are there to France`
  - The assistant mapped France to `outside_counterparty_jurisdiction=FR`, which means "not France" rather than "to France".
  - The flow also tried to answer through graph seed neighborhoods, causing random Panama-node seeds to drive transaction lookup.
- Data validation:
  - `dh_dim_counterparty_account` stores counterparty attributes in `attr_json`.
  - Local Data Hub had:
    - 17 counterparty accounts with `jurisdiction = FR`
    - 17 linked cash facts for those counterparties
    - 1 outbound wire to `FR`
- Fixes:
  - `amlInsights/main.py`
    - Added deterministic country phrase mapping so `to France` maps to:
      - `counterparty_jurisdiction = FR`
      - outbound direction
    - Removed stale template `outside_country_code_2=US` when a specific counterparty jurisdiction is mapped.
    - Added global aggregate detection for count-style transaction questions.
    - For global aggregate questions, calls Data Hub:
      - `/api/graph/exposure/transactions/global`
    - Interpreted query now renders as global transaction count instead of showing a misleading graph seed subject.
  - `amlInsightsDataHub/app/graph_layer.py`
    - Added `build_global_cash_transactions(...)`.
  - `amlInsightsDataHub/app/main.py`
    - Added `GET /api/graph/exposure/transactions/global`.
- Verification:
  - Direct Data Hub global route with:
    - `direction=Outbound`
    - `mechanism_contains=Wire`
    - `counterparty_jurisdiction=FR`
  - Returned 1 row:
    - `TXN-EXT-900003730`
    - `counterparty_jurisdiction = FR`
    - `mechanism = Wire`
    - `direction = Outbound`
  - Full amlInsights natural-language path returned:
    - `Interpreted as global transaction count; filters transaction.direction equals Outbound, transaction.mechanism contains Wire, counterparty.jurisdiction equals FR.`
    - `tx_rows = 1`

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

### 2026-04-24 - Next Session Start Point (Fine-Tuning Plan)

- Current status:
  - Exposure flow is improved and graph behavior is \"looking better\", but additional tuning is desired.
- First test to run on return:
  - Question:
    - `Show potential negative news on ARIGATO LIMITED and all payments associated with this customer to counterparties outside the US`
- Validate in this order:
  1. `seed_selection.graph_seed_candidates` contains customer/account/counterparty-first ordering.
  2. `transaction_filter_mapping.applied_filters` maps payment language to wire-compatible filters (especially `mechanism_contains`).
  3. `transaction_evidence.row_count` is non-zero for at least one seed.
  4. `enriched_transaction_nodes` is populated.
  5. Returned `graph_payload.elements.nodes` includes at least some `Account:*` / `CounterpartyAccount:*` nodes from transaction evidence.
  6. Graph UI visually shows those transaction-linked nodes after `Analyze Question`.
- If mismatch remains, next debugging step:
  - Add temporary on-screen debug panel in Exposure UI showing:
    - `seed_selection`
    - `enriched_transaction_nodes`
    - `transaction_filter_mapping`
    - count of account/counterparty nodes present in returned `graph_payload`
- Tuning backlog after baseline pass:
  - Increase or tune transaction-node enrichment limit (currently capped) only if needed.
  - Refine ranking so customer and primary-account contexts dominate initial view for customer-centric questions.
  - Add explicit evidence-citation IDs for enriched transaction paths (edge/node references) in analyst output.

### 2026-04-26 - MacBook Local Reset + Conversational Exposure Search Checkpoint

- New local workspace paths on MacBook Air:
  - `/Users/erichale/Library/Mobile Documents/com~apple~CloudDocs/apps/amlInsights`
  - `/Users/erichale/Library/Mobile Documents/com~apple~CloudDocs/apps/amlredflags`
  - `/Users/erichale/Library/Mobile Documents/com~apple~CloudDocs/apps/amlInsightsDataHub`
- Local environment notes:
  - Copied `.venv` folders were stale/broken from old machine paths and should be recreated with Python 3.13.
  - Use app-local venv dependencies, not Homebrew, for Python packages such as `uvicorn`.
  - `amlInsights/.env` and `amlredflags/.env` local DB URLs were updated/quoted because the Mac path contains `Mobile Documents`:
    - `LOCAL_DATABASE_URL="sqlite:////Users/erichale/Library/Mobile Documents/com~apple~CloudDocs/apps/amlInsights/app.db"`
  - `amlInsightsDataHub/.env` can keep relative local paths:
    - `DATA_HUB_DATABASE_URL=sqlite:///./data_hub.db`
    - `LOCAL_DATA_HUB_DATABASE_URL=sqlite:///./data_hub.db`
  - Startup/migration scripts were hardened to prefer repo-local `.venv/bin` tools and to handle quoted `.env` values:
    - `amlInsights/scripts/start_local.sh`
    - `amlInsights/scripts/migrate_db.sh`
    - `amlredflags/scripts/start_server.sh`
    - `amlredflags/scripts/migrate_db.sh`
    - `amlInsightsDataHub/scripts/start_server.sh`
    - `amlInsightsDataHub/scripts/db_migrate.sh`

- Data Hub graph/exposure fixes:
  - `amlInsightsDataHub/app/graph_layer.py`
  - Exposure seed search now extracts likely entity phrases from analyst questions, so:
    - `I'm looking for negative news on ARIGATO LIMITED and any payments to counterparties outside the US`
    - correctly seeds `Customer:CUST-010 / ARIGATO LIMITED` instead of unrelated Panama nodes that matched generic words.
  - Graph nodes now include `business_key`, which lets transaction detail lookup recover account/counterparty keys from graph node IDs.
  - Surrogate address creation now suppresses country-code-only address signatures to reduce noisy country-only clusters.
  - Shared surrogate nodes are added back into selected subgraphs when two or more selected real nodes share them, so duplicate counterparty names in the returned graph now link through shared `SurrogateName` nodes.

- Data Hub transaction/dimension filters added:
  - `GET /api/graph/exposure/transactions` now supports dimension-aware filters:
    - `outside_counterparty_jurisdiction`
    - `counterparty_jurisdiction`
    - `outside_customer_country_code`
    - `customer_country_code`
    - `outside_branch_country_code`
    - `branch_country_code`
    - `account_type_contains`
    - `account_name_contains`
    - `customer_segment_contains`
    - `customer_business_unit`
    - `branch_type_contains`
  - `GET /api/graph/transaction-filter-catalog` now includes live dimension vocabularies:
    - `counterparty_jurisdictions`
    - `customer_country_codes`
    - `branch_country_codes`
  - Account geography is not currently supported because the current account dimension sample only has:
    - `account_key`, `account_type`, `account_name`
    - Add account country/location attributes before supporting account-country filters.

- `amlInsights` exposure parser/assistant changes:
  - `amlInsights/main.py`
  - Natural language filter mapping now distinguishes:
    - `payments outside the US` -> transaction country filter (`outside_country_code_2=US`)
    - `payments to counterparties outside the US` -> counterparty jurisdiction filter (`outside_counterparty_jurisdiction=US`)
    - customer/branch outside-US wording -> corresponding customer/branch filters
  - The OpenAI filter mapper is still useful, but ambiguous `outside the US` questions now pause for clarification instead of letting OpenAI silently choose a dimension.
  - `ExposureQuestionRequest` now accepts `filter_overrides` so the UI can rerun with a structured clarification choice.
  - `POST /api/entity-search/exposure-question` now returns:
    - `interpreted_query`
    - `clarification` when needed
    - `mode/status = needs_clarification` for ambiguous geography scope

- Exposure UI changes:
  - `amlInsights/templates/exposure_search.html`
  - Added visible `Interpreted Query` section.
  - Added clarification buttons when the backend returns `needs_clarification`.
  - Clicking a clarification button reruns the same question with structured `filter_overrides`.
  - Example ambiguous question expected to show buttons:
    - `Show exposure for ARIGATO LIMITED outside the US`
  - Expected clarification choices:
    - Counterparty jurisdiction
    - Transaction country
    - Customer country
    - Branch country

- Verification completed:
  - Direct Data Hub test for `Customer:CUST-010` with:
    - `outside_counterparty_jurisdiction=US`
    - `direction=Outbound`
    - `mechanism_contains=Wire`
  - Returned non-US counterparty jurisdictions only; no rows had `counterparty_jurisdiction = US`.
  - Parser check for:
    - `I'm looking for negative news on ARIGATO LIMITED and any payments to counterparties outside the US`
  - Expected interpreted query:
    - subject `ARIGATO LIMITED`
    - `transaction.direction equals Outbound`
    - `transaction.mechanism contains Wire`
    - `counterparty.jurisdiction outside US`

- First thing to test next session:
  1. Restart `amlInsights` and `amlInsightsDataHub`.
  2. Hard refresh the browser.
  3. Run:
     - `Show exposure for ARIGATO LIMITED outside the US`
  4. Confirm UI shows clarification buttons under `Interpreted Query`.
  5. Click `Counterparty jurisdiction`.
  6. Confirm rerun interpretation says:
     - `counterparty.jurisdiction outside US`
  7. Confirm transaction evidence excludes US-jurisdiction counterparties.

- Next recommended development step:
  - After the clarification loop feels right, add persisted investigation sessions:
    - `exposure_sessions`
    - `exposure_session_messages`
    - `exposure_session_interpretations`
  - Then support follow-up messages like:
    - `Now only show wires`
    - `Switch outside US to transaction country instead`
    - `Limit to Panama-linked counterparties`

### 2026-04-27 - Exposure Assistant Transaction Section

- Replaced the old Exposure Search/name-search and Search Results UI sections in `templates/exposure_search.html` with a `Transactions` section.
- The transaction section is modeled after the customer-search transaction grid:
  - renders rows identified by the latest assistant interaction from `transaction_evidence[].sample_rows`
  - supports column text filters, date range filters, amount range filtering, and multi-select filters
  - includes transaction, account, AML classification, direction, amount, country, currency, counterparty, counterparty jurisdiction, and source columns
- Moved analysis controls (`resultLimit`, `hops`, `maxNodes`, `maxEdges`) into the Grounded Exposure Assistant panel so question analysis still has the same parameters available after removing the old search form.
- Increased exposure assistant transaction sample rows from 25 to 500 in `main.py` so the UI can display a useful transaction grid rather than only a tiny preview.
- Transaction-driven assistant summaries now prefer the retrieved transaction evidence when transaction rows are present, so global transaction searches do not summarize unrelated seed-search context.
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - `amlInsightsDataHub`: `../amlInsightsDataHub/.venv/bin/python -m py_compile ../amlInsightsDataHub/app/main.py ../amlInsightsDataHub/app/graph_layer.py`
  - `find wires to france` returned 1 global transaction row:
    - `TXN-EXT-900003730`
    - outbound wire
    - `counterparty_jurisdiction = FR`

### 2026-04-27 - End-of-Day Local Status

- Local applications were verified running before close:
  - `amlInsights`: `http://127.0.0.1:8000`
  - `amlInsightsDataHub`: `http://127.0.0.1:8100`
  - Health checks returned:
    - `amlInsights`: `{"status":"ok"}`
    - `amlInsightsDataHub`: `{"ok":true,"service":"data-hub"}`
- Current active `amlInsights` working files:
  - `main.py`
  - `platform_models.py`
  - `templates/exposure_search.html`
  - `docs/application_state_reset.md`
  - `alembic/versions/20260427_0019_add_exposure_sessions.py`
- Current active `amlInsightsDataHub` working files:
  - `app/main.py`
  - `app/graph_layer.py`
- Major features completed today:
  - Persisted exposure investigation sessions.
  - Session-aware follow-up handling with subject/filter carry-forward.
  - Exposure session transcript UI with restore/rerun actions.
  - France-wire global transaction handling:
    - `find wires to france`
    - `how many wires are there to France`
  - Global transaction route in Data Hub:
    - `GET /api/graph/exposure/transactions/global`
  - Exposure Search UI now shows a transaction grid instead of the old exposure name search/results sections.
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - `amlInsightsDataHub`: `../amlInsightsDataHub/.venv/bin/python -m py_compile ../amlInsightsDataHub/app/main.py ../amlInsightsDataHub/app/graph_layer.py`
  - API smoke test for `find wires to france` returned:
    - summary: global transaction search returned 1 row
    - interpreted filters: outbound wire, counterparty jurisdiction `FR`
    - sample transaction: `TXN-EXT-900003730`
- Request-limit note:
  - No application-level request limit was observed during the final verification.
  - Some local `curl` calls from the Codex sandbox needed escalated execution to reach `127.0.0.1`; that was sandbox/network permission behavior, not an app rate limit.
- Known follow-up:
  - The transaction grid is wired from `transaction_evidence[].sample_rows`; it now receives up to 500 sampled rows.
  - Next browser pass should confirm the UI rendering and column filters visually from an authenticated browser session.
  - Consider suppressing graph seed-search execution entirely for global subjectless transaction questions so the audit trail is cleaner, even though the returned transaction evidence and summary are now correct.

### 2026-04-28 - Global Transaction Questions Skip Seed Search

- Cleaned up the exposure question flow for global, subjectless transaction questions.
- `main.py` now maps transaction filters before running exposure seed search.
- When the question qualifies as a global transaction query, for example:
  - `find wires to france`
  - `how many wires are there to France`
- The flow now:
  - removes `seed_search` and `graph_expansion` from the structured query plan
  - skips `/api/graph/exposure-seed-search`
  - skips graph expansion
  - runs only transaction filter mapping and `/api/graph/exposure/transactions/global`
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - API smoke test for `find wires to france` returned:
    - `queried_data` steps: `transaction_filter_mapping`, `global_transaction_details`
    - structured plan steps: `transaction_details`, `grounded_summary`
    - `evidence_count = 0`
    - `graph_seed_node_id = null`
    - `tx_rows = 1`
    - interpreted query: outbound wire, counterparty jurisdiction `FR`
  - Counter-check for `Show exposure for ARIGATO LIMITED outside the US` still runs:
    - `seed_search`
    - `graph_expansion`
    - `transaction_filter_mapping`
    - returns `needs_clarification` for the ambiguous outside-US dimension.

### 2026-04-28 - Follow-Up Filter Cleanup for France Counterparty Questions

- Issue found from analyst feedback:
  - Follow-up question:
    - `I was looking for all transactions sent to counterparties in France`
  - The response could inherit stale prior filters such as:
    - `outside_country_code_2 = US`
    - `mechanism_contains = wire`
  - That was incorrect because the question asks for all outbound transactions to counterparties in France, not non-US transaction-country wires.
- Fixes in `main.py`:
  - Deterministic transaction filter mapping now recognizes counterparty geography phrasing:
    - `counterparties in France`
    - `beneficiaries in France`
    - `recipients in France`
  - This maps to:
    - `counterparty_jurisdiction = FR`
    - outbound direction when paired with sent/to-counterparty wording.
  - Template defaults are now stripped unless explicitly supported by the question or inherited overrides:
    - `outside_country_code_2`
    - `mechanism_contains`
  - In follow-up override handling:
    - `all transactions` clears inherited mechanism/classification filters.
    - explicit country/counterparty phrasing clears inherited geography filters before setting `counterparty_jurisdiction`.
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - Direct question returned:
    - `direction = Outbound`
    - `counterparty_jurisdiction = FR`
    - `outside_country_code_2 = null`
    - `mechanism_contains = null`
    - `tx_rows = 1`
  - Follow-up regression with prior stale filters also returned:
    - `direction = Outbound`
    - `counterparty_jurisdiction = FR`
    - `outside_country_code_2 = null`
    - `mechanism_contains = null`
    - `tx_rows = 1`

### 2026-04-28 - Structured Query Plan Reflects Normalized Transaction Filters

- Issue found from analyst feedback:
  - A new-session question:
    - `find wires to france`
  - Returned the correct transaction evidence, but the displayed `structured_query_plan` still showed stale template params:
    - `endpoint = /api/graph/exposure/transactions`
    - `outside_country_code_2 = US`
    - old note about wire/outside-US seed detail rows
  - Root cause:
    - Execution used normalized transaction filters, but the plan displayed the original intent template params.
- Fix in `main.py`:
  - After transaction filters are normalized, the transaction plan step is synchronized to the actual execution params.
  - For global transaction questions, the plan step now shows:
    - `endpoint = /api/graph/exposure/transactions/global`
    - `limit = 10000`
    - `direction = Outbound`
    - `mechanism_contains = Wire`
    - `counterparty_jurisdiction = FR`
    - no `outside_country_code_2`
    - note: `Run globally against cash facts for the interpreted transaction filters.`
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - API smoke test for `find wires to france` returned:
    - structured plan endpoint: `/api/graph/exposure/transactions/global`
    - structured plan filters include `counterparty_jurisdiction = FR`
    - structured plan filters do not include `outside_country_code_2`
    - queried data steps: `transaction_filter_mapping`, `global_transaction_details`
    - sample transaction: `TXN-EXT-900003730`

### 2026-04-28 - Exposure Graph Clears for New/Graphless Analyses

- Issue found from analyst feedback:
  - After creating a new exposure session and asking a global transaction question, the old graph visualization remained from the prior question.
  - Root cause:
    - The frontend only rendered a graph when `graph_payload` existed.
    - It did not clear the existing Cytoscape instance when the new response had no graph payload.
- Fix in `templates/exposure_search.html`:
  - `New Session` now clears the current analysis pane and graph visualization.
  - `Analyze Question` now clears the graph when the response has no `graph_payload`.
  - Restoring a saved interpretation now either renders the saved graph or clears the graph if no graph was saved.
  - `clearGraph` now supports a silent option so automatic state cleanup does not show a noisy `Graph cleared` message.
- Expected behavior:
  - Global transaction questions such as `find wires to france` should leave the graph panel empty with a detail hint instead of showing stale nodes from a prior investigation.

### 2026-04-28 - Follow-Up Expansion to Any France Counterparty Transaction

- Issue found from analyst feedback:
  - Analyst asked, in order:
    1. `find wires to france`
    2. `lets expand this search to any transaction with a counterparty in France`
  - First question returned one outbound France wire.
  - Second question returned no transactions and appeared to start with entity seed search, which could route away from the France counterparty nexus.
- Root causes:
  - Global transaction detection did not treat singular `transaction`, `any transaction`, or `expand` as global transaction language.
  - Follow-up cleanup cleared wire filters for `all transactions`, but not for `any transaction`.
  - The transaction template could still contribute stale defaults:
    - `mechanism_contains = wire`
    - `direction = outbound`
- Fixes in `main.py`:
  - Global transaction detection now recognizes:
    - singular `transaction`
    - `any`
    - `expand`
  - Follow-up detection now recognizes starts such as:
    - `lets ...`
    - `let's ...`
  - Broad transaction follow-ups such as `any transaction` or `expand ... transaction` now clear inherited:
    - `mechanism_contains`
    - `aml_classification_contains`
    - `direction`, unless the new question explicitly says sent/outbound/inbound/received.
  - Normalized transaction filters now strip template `direction` unless the current wording or explicit override supports it.
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - Two-step session regression:
    1. `find wires to france`
       - global transaction details
       - `direction = Outbound`
       - `mechanism_contains = Wire`
       - `counterparty_jurisdiction = FR`
       - `tx_rows = 1`
    2. `lets expand this search to any transaction with a counterparty in France`
       - global transaction details
       - no seed search
       - `direction = null`
       - `mechanism_contains = null`
       - `counterparty_jurisdiction = FR`
       - `tx_rows = 4`

### 2026-04-28 - Exposure UI JSON Accordions + Transaction Mechanism Column

- UI changes in `templates/exposure_search.html`:
  - JSON/debug outputs now use nested accordion sections and are collapsed by default:
    - Interpreted Query JSON
    - What Data Was Queried
    - Structured Query Plan
    - Relationship Findings
    - Audit
  - Transaction table now includes a `mechanism` column.
  - Transaction table filtering now supports mechanism:
    - text filter
    - multi-select filter
    - clear-filter reset
- Notes:
  - Existing JSON render targets were preserved (`qaInterpretedQuery`, `qaQueriedData`, `qaPlan`, `qaFindings`, `qaAudit`) so the current JavaScript render path continues to update them.
  - A local Node.js syntax check was not available because `node` is not installed in the current shell.

### 2026-04-28 - Next Step: Capabilities Catalog and Interpretation Regression Plan

- Added a follow-on implementation plan:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- This should be the next major development thread after the current exposure UI/interpreter tuning stabilizes.
- Plan objective:
  - Let `amlInsightsDataHub` declare what graph nodes, edges, endpoints, dimensions, and filters it supports.
  - Let `amlInsights` interpret analyst language against those declared capabilities instead of relying on scattered hardcoded assumptions.
  - Add regression infrastructure so interpretation behavior can be tuned safely as new data is added to Data Hub and the graph.
- Recommended next execution order:
  1. Build `GET /api/graph/capabilities` in Data Hub.
  2. Add a small `amlInsights` capability client.
  3. Create the exposure interpretation regression case schema.
  4. Build the local regression runner.
  5. Seed the runner with the recent France/outside-US/follow-up cases.
  6. Use the runner for every future interpretation change.
  7. Add an Interpretation Lab UI later, after file-based tests exist.

### 2026-04-28 - Started Phase 1 Data Hub Capabilities Catalog

- Began executing:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- Data Hub changes:
  - Added `amlInsightsDataHub/app/capability_catalog.py`.
  - Added endpoint:
    - `GET /api/graph/capabilities`
- Initial capabilities response includes:
  - graph endpoints
  - graph node types
  - graph edge types
  - seed-search node types
  - seeded transaction search capability
  - global transaction search capability
  - supported transaction filters
  - live transaction vocabularies from the existing transaction filter catalog
  - source table/field metadata for key dimensions:
    - counterparty jurisdiction
    - transaction country
    - customer country
    - branch country
    - transaction type
- Verification completed:
  - `amlInsightsDataHub`: `../amlInsightsDataHub/.venv/bin/python -m py_compile ../amlInsightsDataHub/app/main.py ../amlInsightsDataHub/app/capability_catalog.py`
  - Local endpoint smoke test:
    - `GET http://127.0.0.1:8100/api/graph/capabilities`
    - returned version `2026-04-28.v1`
    - returned graph node/edge types
    - returned global and seeded transaction capability metadata
    - returned live vocabularies including directions, mechanisms, country codes, and counterparty jurisdictions
- Next step:
  - Add a small `amlInsights` capability client that calls `/api/graph/capabilities` and starts using it in interpretation/filter validation.

### 2026-04-28 - Started Phase 2 amlInsights Capability Client

- Began Phase 2 from:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- `amlInsights/main.py` changes:
  - Added Data Hub capability client helpers:
    - `_get_data_hub_capabilities`
    - `_capability_supports_global_transactions`
    - `_capability_transaction_filter_parameters`
    - `_capability_seed_node_types`
    - `_transaction_filter_catalog_from_capabilities`
    - `_filter_supported_transaction_filters`
  - Exposure question handling now fetches Data Hub capabilities once per question.
  - Transaction filter normalization now:
    - prefers vocabularies from `/api/graph/capabilities`
    - falls back to `/api/graph/transaction-filter-catalog` if capabilities are unavailable
    - drops unsupported transaction filters based on declared Data Hub support
    - preserves operational params such as `hops`, `limit`, and graph include flags
  - Global transaction routing now checks the Data Hub-declared global transaction capability.
  - Seeded transaction node type filtering now uses Data Hub-declared seeded transaction node types.
  - Transaction filter mapping audit now includes:
    - `data_hub_capabilities_version`
    - `supported_filters`
    - `dropped_unsupported_filters`
- Verification completed:
  - `amlInsights`: `.venv/bin/python -m py_compile main.py platform_models.py`
  - Smoke test for `find wires to france`:
    - used Data Hub capabilities version `2026-04-28.v1`
    - supported filter count `15`
    - no unsupported filters dropped
    - global transaction details
    - `tx_rows = 1`
  - Counter-check for a transaction/outside-US question:
    - used Data Hub capabilities version `2026-04-28.v1`
    - no unsupported filters dropped
    - applied declared filters successfully.
- Next step:
  - Start Phase 3 by defining the exposure interpretation regression case schema and seed case files.

### 2026-04-28 - Started Phase 3 Exposure Interpretation Regression Case Format

- Began Phase 3 from:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- Added regression case structure:
  - `tests/exposure_interpretation/README.md`
  - `tests/exposure_interpretation/case_schema.json`
  - `tests/exposure_interpretation/cases/france_transactions.json`
  - `tests/exposure_interpretation/cases/followup_expansion.json`
  - `tests/exposure_interpretation/cases/outside_us_clarification.json`
  - `tests/exposure_interpretation/cases/entity_scoped_exposure.json`
- Case schema supports:
  - single-turn and multi-turn session flows
  - optional `filter_overrides`
  - expected queried steps
  - expected forbidden queried steps
  - expected structured plan endpoints
  - expected transaction filters
  - transaction row bounds
  - sample transaction IDs
  - clarification expectations
  - graph/evidence count bounds
- Seeded cases cover:
  - `find wires to france`
  - `I was looking for all transactions sent to counterparties in France`
  - `lets expand this search to any transaction with a counterparty in France`
  - outside-US ambiguity for `ARIGATO LIMITED`
  - counterparty-jurisdiction clarification
  - switching outside-US from counterparty jurisdiction to transaction country
  - entity-scoped ARIGATO exposure seed search
- Verification completed:
  - JSON parse validation succeeded for:
    - schema file
    - all four case files
  - Total initial cases: 7
- Next step:
  - Start Phase 4 by building `tests/exposure_interpretation/runner.py` to execute these cases against local `amlInsights`.

### 2026-04-28 - Started Phase 4 Local Exposure Interpretation Regression Runner

- Began Phase 4 from:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- Added and hardened:
  - `tests/exposure_interpretation/runner.py`
  - `tests/exposure_interpretation/__init__.py`
- Runner behavior:
  - reads all JSON case files under `tests/exposure_interpretation/cases/`
  - creates temporary exposure sessions when cases request session context
  - posts each turn to `/api/entity-search/exposure-question`
  - supports optional `filter_overrides` for clarification choices
  - checks:
    - response mode/status/scope
    - ordered queried steps
    - forbidden queried steps
    - ordered structured plan endpoints
    - applied transaction filters
    - transaction row count bounds
    - sampled transaction keys
    - clarification presence and labels
    - evidence count bounds
- Runner command:
  - `.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000`
- Verification completed:
  - `.venv/bin/python -m py_compile main.py tests/exposure_interpretation/runner.py`
  - Local regression suite passed:
    - `Exposure interpretation regression: 9/9 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
- Backend behavior fixed while wiring Phase 4:
  - Explicit clarification `filter_overrides` now add a transaction-details plan step even when the original intent routed as graph-only exposure.
  - Ambiguous outside-US exposure questions now add transaction filter mapping so the app can ask which geography dimension should be used before running transaction evidence.
- Next step:
  - Move to Phase 5 by adding more seed cases from current and future tuning work, then use this runner before and after each interpretation change.

### 2026-04-28 - Started Phase 5 Seed Exposure Interpretation Regression Suite

- Began Phase 5 from:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- Added case files:
  - `tests/exposure_interpretation/cases/france_transaction_variants.json`
  - `tests/exposure_interpretation/cases/outside_us_dimension_hints.json`
- Expanded regression coverage:
  - total runner turns increased from 9 to 16
  - added France/global transaction variants:
    - `how many wires are there to France`
    - `find transactions to counterparties in France`
    - `find any transactions with a counterparty in France`
  - added explicit outside-US dimension hint cases:
    - transaction country outside the US
    - counterparties outside the US
    - customer country outside the US
    - branch country outside the US
- Backend behavior fixed while seeding Phase 5:
  - Entity-scoped exposure questions such as `Show exposure for ARIGATO LIMITED with transaction country outside the US` now remain seed-scoped instead of being converted into global transaction searches.
  - Explicit outside-US dimension hints now add a transaction-details planning step when the original intent routes as graph-only, allowing the deterministic mapper to apply the requested geography dimension.
- Verification completed:
  - `.venv/bin/python -m py_compile main.py tests/exposure_interpretation/runner.py`
  - `.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000`
  - Result:
    - `Exposure interpretation regression: 16/16 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
- Next step:
  - Continue adding cases as new interpretation feedback arrives, or move to Phase 6 to document the runner workflow and optionally add a wrapper script.

### 2026-04-28 - Started Phase 6 Exposure Interpretation Developer Workflow

- Began Phase 6 from:
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
- Added workflow documentation:
  - `docs/exposure_interpretation_regression.md`
- Added executable scripts:
  - `scripts/check_local_exposure_apps.sh`
  - `scripts/run_exposure_interpretation_regression.sh`
- Health-check script verifies:
  - `amlInsights` health:
    - `http://127.0.0.1:8000/health`
  - `amlInsightsDataHub` health:
    - `http://127.0.0.1:8100/health`
  - Data Hub capability catalog:
    - `http://127.0.0.1:8100/api/graph/capabilities`
- Regression wrapper behavior:
  - runs the health-check script first
  - runs `tests.exposure_interpretation.runner`
  - defaults to:
    - `AML_INSIGHTS_BASE_URL=http://127.0.0.1:8000`
    - `DATA_HUB_BASE_URL=http://127.0.0.1:8100`
    - `AML_USER_EMAIL=investigator@tenant1.com`
  - passes through runner args such as:
    - `--case france`
- Verification completed:
  - `bash -n scripts/check_local_exposure_apps.sh`
  - `bash -n scripts/run_exposure_interpretation_regression.sh`
  - `./scripts/check_local_exposure_apps.sh`
  - `./scripts/run_exposure_interpretation_regression.sh`
  - Wrapper result:
    - `Exposure interpretation regression: 16/16 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
- Next step:
  - Continue using `./scripts/run_exposure_interpretation_regression.sh` as the standard local safety check before and after interpretation changes.
  - Later optional hardening: wire the wrapper into CI once stable local fixture services are available.

### 2026-04-28 - Russia Transaction Interpretation Fix

- Issue found from analyst feedback:
  - Question:
    - `I am looking for transactions to Russia`
  - The structured plan used:
    - `outside_counterparty_jurisdiction = RU`
  - That means counterparty jurisdiction is not Russia, so it returned many non-Russia transactions.
- Root cause:
  - The deterministic country phrase map did not include Russia/Russian Federation.
  - The OpenAI fallback mapped the unsupported deterministic gap to the wrong outside-country filter.
- Fix in `main.py`:
  - Added deterministic aliases:
    - `russia = RU`
    - `russian federation = RU`
  - `to Russia` now maps to:
    - `counterparty_jurisdiction = RU`
    - `direction = Outbound`
  - It does not map to:
    - `outside_counterparty_jurisdiction = RU`
- Added regression case:
  - `tests/exposure_interpretation/cases/russia_transactions.json`
- Verification completed:
  - Data Hub direct check:
    - `counterparty_jurisdiction=RU` returned `7` rows
    - `outside_counterparty_jurisdiction=RU` returned `2444` rows, confirming the observed overbroad result
  - `.venv/bin/python -m py_compile main.py tests/exposure_interpretation/runner.py`
  - Focused runner:
    - `./scripts/run_exposure_interpretation_regression.sh --case russia`
    - `Exposure interpretation regression: 1/1 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
  - Full runner:
    - `./scripts/run_exposure_interpretation_regression.sh`
    - `Exposure interpretation regression: 17/17 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`

### 2026-04-28 - Country Alias Resolver Configuration

- Follow-up hardening from the Russia issue:
  - Moved country name to ISO-2 resolution out of `main.py`.
- Added:
  - `config/country_aliases.json`
  - `country_resolution.py`
  - `tests/test_country_resolution.py`
- Resolver behavior:
  - loads canonical country names and ISO codes from:
    - `../amlInsightsDataHub/data/sample/dh_dim_country_sample.csv`
  - layers manual analyst aliases from:
    - `config/country_aliases.json`
  - keeps fallback aliases for critical common names if the config/source file is unavailable
  - returns aliases longest-first so longer names win before short aliases:
    - `russian federation` before `russia`
    - `united states` before `us`
- `main.py` now imports:
  - `iter_country_aliases`
- Removed the local `_COUNTRY_NAME_TO_CODE_2` mapping from `main.py`.
- Verification completed:
  - `.venv/bin/python -m py_compile main.py country_resolution.py tests/test_country_resolution.py tests/exposure_interpretation/runner.py`
  - `.venv/bin/python -m unittest tests.test_country_resolution`
    - `Ran 2 tests`
    - `OK`
  - `./scripts/run_exposure_interpretation_regression.sh --case russia`
    - `Exposure interpretation regression: 1/1 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
  - `./scripts/run_exposure_interpretation_regression.sh`
    - `Exposure interpretation regression: 17/17 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`

### 2026-04-28 - Expanded Country Alias Overlay

- Expanded:
  - `config/country_aliases.json`
- Added broader analyst-friendly aliases and variants, including:
  - common shorthand:
    - `uae`, `prc`, `uk`, `usa`
  - common/alternate names:
    - `ivory coast`, `burma`, `turkiye`, `vietnam`
  - official-name variants:
    - `democratic republic of the congo`, `syrian arab republic`, `islamic republic of iran`
  - regional/SAR references:
    - `hong kong`, `macau`, `taiwan`
  - directional Korea variants:
    - `south korea`, `north korea`
  - selected demonyms:
    - `russian`, `french`, `american`, `british`, `iranian`, `syrian`
- Expanded resolver tests in:
  - `tests/test_country_resolution.py`
- Verification completed:
  - `.venv/bin/python -m json.tool config/country_aliases.json`
  - `.venv/bin/python -m py_compile country_resolution.py tests/test_country_resolution.py main.py`
  - `.venv/bin/python -m unittest tests.test_country_resolution`
    - `Ran 2 tests`
    - `OK`
  - `./scripts/run_exposure_interpretation_regression.sh`
    - `Exposure interpretation regression: 17/17 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`

### 2026-04-28 - Follow-Up Context Boundary for New Counterparty Nexus Search

- Issue found from analyst feedback:
  - First question asked for transactions from China.
  - Follow-up/new question:
    - `show me counterparties that have a Russian nexus`
  - The prior transaction filters were inherited:
    - `direction = Outbound`
    - `counterparty_jurisdiction = CN`
  - This incorrectly limited the Russian nexus counterparty search to the prior China transaction context.
- Root cause:
  - `_looks_like_followup` treated any occurrence of the word `that` as a follow-up signal.
  - In `counterparties that have a Russian nexus`, `that` is just part of a relative clause, not a reference to the previous answer.
  - The phrase `Russian nexus` also needed deterministic positive-country handling to avoid the wrong outside-country polarity.
- Fixes in `main.py`:
  - Removed bare `that` from generic follow-up indicators.
  - Added deterministic mapping for country nexus phrases:
    - `{country alias} nexus`
    - `nexus to/with/in/within {country alias}`
  - `Russian nexus` now maps to:
    - `counterparty_jurisdiction = RU`
  - It does not map to:
    - `outside_counterparty_jurisdiction = RU`
  - Subjectless counterparty-country nexus questions now add a transaction-details planning step and can route globally instead of running lexical graph seed search against unrelated Panama nodes.
- Behavior clarified:
  - `show me counterparties that have a Russian nexus` should not choose a subject such as `CONSORCIO DE ABOGADOS JIMENEZ SALAS Y ASOCIADOS`.
  - It should run as a subjectless counterparty/country query with:
    - `counterparty_jurisdiction = RU`
    - no inherited China filters
    - no graph seed search
- Added regression case:
  - `tests/exposure_interpretation/cases/followup_context_boundaries.json`
  - Covers:
    1. `I am looking for transactions from China`
    2. `show me counterparties that have a Russian nexus`
- Verification completed:
  - `.venv/bin/python -m py_compile main.py`
  - `./scripts/run_exposure_interpretation_regression.sh --case china_transaction_then_russian`
    - `Exposure interpretation regression: 2/2 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
  - `./scripts/run_exposure_interpretation_regression.sh`
    - `Exposure interpretation regression: 19/19 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`

### 2026-04-28 - Transaction-Linked Graph Enrichment for Follow-Up Negative News

- Issue found from analyst feedback:
  - After a transaction-backed counterparty query, the follow-up:
    - `is there any negative news linked to those counterparties`
  - returned transaction evidence but did not populate the entity graph.
- Root cause:
  - Graph enrichment only ran when a graph payload already existed from seed search.
  - Global transaction-backed questions can return transaction rows and counterparty node IDs without an initial seed-search graph payload.
- Fix in `main.py`:
  - Transaction-linked node enrichment can now bootstrap the graph when:
    - `include_graph = true`
    - transaction rows identify account or counterparty node IDs
    - no prior seed-search graph payload exists
  - The first transaction-linked node graph becomes the initial `graph_payload`.
  - Additional transaction-linked node graphs are merged into it.
- Regression runner enhancements:
  - Added expectations:
    - `min_enriched_transaction_nodes`
    - `min_graph_nodes`
  - Updated:
    - `tests/exposure_interpretation/runner.py`
    - `tests/exposure_interpretation/case_schema.json`
    - `tests/exposure_interpretation/README.md`
- Regression case expanded:
  - `tests/exposure_interpretation/cases/followup_context_boundaries.json`
  - Now covers:
    1. `I am looking for transactions from China`
    2. `show me counterparties that have a Russian nexus`
    3. `is there any negative news linked to those counterparties`
- Verification completed:
  - `.venv/bin/python -m py_compile main.py tests/exposure_interpretation/runner.py`
  - JSON validation for:
    - `tests/exposure_interpretation/case_schema.json`
    - `tests/exposure_interpretation/cases/followup_context_boundaries.json`
  - Focused runner:
    - `./scripts/run_exposure_interpretation_regression.sh --case china_transaction_then_russian`
    - `Exposure interpretation regression: 3/3 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
  - Full runner:
    - `./scripts/run_exposure_interpretation_regression.sh`
    - `Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`

### 2026-04-28 - End-of-Day Reset: Exposure Interpretation Hardening

- Current local app assumptions:
  - `amlInsights`:
    - `http://127.0.0.1:8000`
  - `amlInsightsDataHub`:
    - `http://127.0.0.1:8100`
  - Health/regression workflow:
    - `./scripts/check_local_exposure_apps.sh`
    - `./scripts/run_exposure_interpretation_regression.sh`
- Current verified baseline:
  - `Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
- Major completed thread:
  - Built Data Hub capabilities catalog.
  - Wired `amlInsights` to consume Data Hub capabilities.
  - Created exposure interpretation regression case format.
  - Built local regression runner.
  - Seeded and expanded regression suite.
  - Added developer workflow docs/scripts.
  - Moved country alias resolution out of `main.py` into config-backed resolver.
  - Fixed Russia/RU polarity issues.
  - Fixed stale follow-up context for new counterparty/nexus questions.
  - Fixed transaction-linked graph enrichment for follow-up negative-news questions.
- Important files in the current work:
  - `main.py`
  - `templates/exposure_search.html`
  - `config/country_aliases.json`
  - `country_resolution.py`
  - `docs/data_hub_capabilities_and_interpretation_regression_plan.md`
  - `docs/data_hub_capabilities_and_regression_implementation_results.md`
  - `docs/exposure_interpretation_regression.md`
  - `scripts/check_local_exposure_apps.sh`
  - `scripts/run_exposure_interpretation_regression.sh`
  - `tests/test_country_resolution.py`
  - `tests/exposure_interpretation/`
- Current Data Hub files from this thread:
  - `../amlInsightsDataHub/app/main.py`
  - `../amlInsightsDataHub/app/capability_catalog.py`
- Known uncommitted/generated item:
  - `.DS_Store` appears untracked in `amlInsights`; it is unrelated and should not be committed.
- Recommended next restart point:
  1. Read this reset section and:
     - `docs/data_hub_capabilities_and_regression_implementation_results.md`
     - `docs/exposure_interpretation_regression.md`
  2. Confirm local services:
     - `./scripts/check_local_exposure_apps.sh`
  3. Run the safety suite:
     - `./scripts/run_exposure_interpretation_regression.sh`
  4. Continue from analyst feedback by adding or updating regression cases first, then changing interpretation code.
- Potential next product improvement:
  - Add clearer UI context indicators:
    - whether prior session context was used
    - which filters were inherited
    - whether a question was treated as standalone
  - Add a visible `clear context` or `ask as new question` control near the exposure question box.

### 2026-04-29 - Refactor Plan and Backlog Added

- Added `docs/main_module_refactor_plan.md`.
  - Purpose: plan a behavior-preserving split of the oversized `main.py` into logical exposure, Data Hub, route, and UI modules.
- Added `docs/engineering_backlog.md`.
  - Purpose: keep durable product and engineering work separate from this daily handoff/reset document.
- Backlog items now include:
  - Main module refactor.
  - Exposure context UX.
  - CI execution with fixture Data Hub services.
  - Interpretation Lab UI.
  - Distinct counterparty result capability.
  - External negative news integration.
  - Data Hub capability catalog hardening.
  - Country alias governance.
  - Repository hygiene.
- Recommended use:
  - Continue using this file for session reset and current-state handoff.
  - Use `docs/engineering_backlog.md` as the persistent list of future work.
  - Use `docs/main_module_refactor_plan.md` when ready to start the `main.py` modularization.

### 2026-04-30 - Daily Close: Exposure Graph Visualization

- Main work completed today:
  - Tuned Exposure Search graph visualization for transaction-heavy counterparty graphs.
  - Prevented `CounterpartyAccount:NA` from being used as a graph enrichment seed.
  - Added initial graph limiting so the first view shows the top 4 counterparties by transaction amount.
  - Added a `CounterpartyRemainder` aggregate node for hidden/non-top counterparties.
  - Connected the aggregate node to account/customer anchors when possible.
  - Removed orphan/disconnected name/address surrogate nodes from the initial pruned graph.
  - Adjusted aggregate expansion so it expands to real counterparty nodes without immediately opening high-degree name/address surrogate neighborhoods.
- Important implementation files:
  - `main.py`
    - Backend transaction-counterparty pruning and aggregate node insertion.
    - Excludes `CounterpartyAccount:NA` from transaction-linked enrichment seeds.
  - `templates/exposure_search.html`
    - Renders `CounterpartyRemainder`.
    - Supports double-click expansion of the aggregate node.
    - Compacts deferred counterparty expansion to avoid surrogate clutter.
- Behavior verified on:
  - `I am looking for transactions to Russia`
    - Graph payload contained 4 visible `CounterpartyAccount` nodes.
    - Graph payload contained 1 `CounterpartyRemainder` aggregate node.
    - Orphan surrogate nodes count was 0 in the checked payload.
- Interpretation fix completed today:
  - `search for negative news associated with ARIGATO LIMITED` now extracts/seeds on the entity phrase instead of searching the full sentence.
  - Added regression coverage for the associated-with wording.
- Current verified baseline:
  - `.venv/bin/python -m py_compile main.py country_resolution.py`
  - `.venv/bin/python -m unittest tests.test_country_resolution`
  - `./scripts/run_exposure_interpretation_regression.sh`
    - `Exposure interpretation regression: 21/21 turn(s) passed (0 failed turn(s), 0 assertion failure(s))`
- Backlog updates:
  - `docs/engineering_backlog.md`
    - Expanded `CI Execution With Fixture Data Hub Services` and marked it `Ready`.
    - Added `Data Hub Counterparty Graph Aggregation` and marked it `Ready`.
- Architecture note:
  - Current counterparty aggregation is prototyped in `amlInsights`.
  - Longer-term preferred direction is to move this graph aggregation/collapse behavior into `amlInsightsDataHub` so Data Hub returns smaller graph payloads and owns graph semantics.
- Current local app assumptions:
  - `amlInsights`: `http://127.0.0.1:8000`
  - `amlInsightsDataHub`: `http://127.0.0.1:8100`
  - Health check:
    - `./scripts/check_local_exposure_apps.sh`
- Recommended next restart point:
  1. Hard-refresh the browser before testing graph changes.
  2. Re-test:
     - `I am looking for transactions to Russia`
     - `find negative news related to ARIGATO LIMITED`
     - `search for negative news associated with ARIGATO LIMITED`
  3. Confirm aggregate-node expansion feels right:
     - top 4 counterparties visible initially
     - `Other counterparties (N)` visible
     - double-click aggregate expands counterparties
     - name/address surrogate nodes remain compressed until deliberately expanded
  4. If the UI feels right, start the backlog item:
     - `Data Hub Counterparty Graph Aggregation`
     - move aggregate/collapse behavior from `amlInsights` into `amlInsightsDataHub`.
- Known uncommitted/generated item:
  - `.DS_Store` appears untracked in `amlInsights`; it is unrelated and should not be committed.
