# Main Module Refactor Plan

## Goal

Refactor `main.py` into smaller, logical modules while preserving the current API surface, UI behavior, and exposure interpretation results.

The intent is not to redesign the application. The intent is to make future changes safer by moving related code into focused modules and running the exposure interpretation regression suite after each extraction.

## Why This Matters

`main.py` has become the center of gravity for several different responsibilities:

- FastAPI app setup, middleware, and route registration.
- Exposure question interpretation and execution.
- Intent loading, routing, and query plan rendering.
- Data Hub proxy calls and capabilities catalog handling.
- Transaction filter mapping and follow-up context resolution.
- Graph evidence assembly and transaction-linked enrichment.
- Session persistence.
- Red flags, tenant, platform, and UI routes.

That worked while the product was forming, but it now makes interpretation changes harder to reason about. The exposure capability is becoming the most valuable part of the application, so it deserves clearer module boundaries and better local test leverage.

## Refactor Principles

- Preserve behavior first.
- Keep public API paths unchanged.
- Extract one responsibility at a time.
- Prefer pure helper modules before moving route handlers.
- Run regression checks after each meaningful extraction.
- Avoid broad rewrites, renames, or style-only churn.
- Keep `main.py` as the app composition layer until the route modules are stable.

## Proposed Target Shape

```text
main.py
  FastAPI app creation, middleware, static/templates setup, router inclusion.

country_resolution.py
  Existing extracted country alias and ISO code resolution helpers.

exposure/
  __init__.py
  routes.py
    Exposure API routes and request/response wiring.
  intents.py
    Intent config loading, intent scoring, routing, query plan templating.
  filters.py
    Transaction filter extraction, normalization, capability-supported filtering.
  followup.py
    Follow-up detection, inherited context handling, standalone question detection.
  execution.py
    Query plan execution orchestration and evidence collection.
  graph.py
    Graph result normalization, transaction-linked graph enrichment helpers.
  summaries.py
    Grounded summary construction and evidence-constrained response helpers.
  sessions.py
    Exposure session persistence and retrieval helpers.

data_hub/
  __init__.py
  client.py
    Data Hub base URL resolution, proxy JSON requests, health helper.
  capabilities.py
    Data Hub capabilities catalog fetch, cache, and capability lookup helpers.

red_flags/
  routes.py
    Red flags workspace API routes.

platform_admin/
  routes.py
    Platform and tenant administrative routes.

ui/
  routes.py
    HTML page rendering routes.
```

The final shape can change as the extraction teaches us more. The key point is that exposure interpretation, Data Hub access, and route registration should stop being interleaved in one file.

## Phase 1: Inventory and Baseline

Create a short inventory of the major function groups in `main.py`.

Capture the current safety baseline:

```bash
.venv/bin/python -m py_compile main.py country_resolution.py
.venv/bin/python -m unittest tests.test_country_resolution
./scripts/run_exposure_interpretation_regression.sh
```

Expected baseline at the start of this plan:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

## Phase 2: Extract Pure Exposure Helpers

Move pure or mostly pure helpers first because they are easiest to verify.

Candidate extraction areas:

- Intent config loading and scoring.
- Intent query plan template rendering.
- Transaction filter normalization.
- Supported filter pruning from Data Hub capabilities.
- Follow-up detection and inherited filter handling.
- Graph evidence summarization helpers.

Acceptance criteria:

- `main.py` imports helpers from `exposure/*`.
- Route behavior remains unchanged.
- Existing exposure regression suite still passes.

## Phase 3: Extract Data Hub Client and Capabilities

Move Data Hub connection logic out of `main.py`.

Candidate extraction areas:

- Base URL/environment resolution.
- Shared JSON request/proxy helpers.
- Capabilities catalog fetch and caching.
- Capability checks such as global transaction support and supported filter parameters.

Acceptance criteria:

- Data Hub-related helpers live under `data_hub/*`.
- Existing API endpoints still call the same Data Hub routes.
- Capability-driven filter mapping continues to expose version, supported filters, and dropped unsupported filters.

## Phase 4: Extract Exposure Execution

Move the orchestration logic that turns an interpreted question into executed Data Hub and graph calls.

Candidate extraction areas:

- Seed search suppression for transaction-global questions.
- Global transaction execution.
- Seed-scoped transaction execution.
- Transaction-linked graph enrichment.
- Evidence bundle construction.

Acceptance criteria:

- Regression cases for France, Russia, China follow-up, and transaction-linked graph enrichment still pass.
- No API response schema regressions for the exposure question endpoint.

## Phase 5: Extract Exposure Routes and Sessions

Once the helper modules are stable, move exposure-specific route handlers and session storage helpers into an exposure router.

Acceptance criteria:

- `main.py` includes the exposure router.
- Exposure routes remain available at their current paths.
- Existing UI continues to call the same endpoints.
- Session behavior remains compatible with existing local session files.

## Phase 6: Split Non-Exposure Route Domains

After exposure is cleanly separated, move other application domains into route modules.

Candidate route groups:

- Red flags workspace.
- Tenant and platform administration.
- UI page rendering.
- Static or diagnostic endpoints.

Acceptance criteria:

- `main.py` becomes mostly app composition.
- Route paths remain stable.
- Local smoke checks still pass.

## Safety Checks

Run these after each extraction phase:

```bash
.venv/bin/python -m py_compile main.py country_resolution.py
.venv/bin/python -m unittest tests.test_country_resolution
./scripts/run_exposure_interpretation_regression.sh
```

When route modules are introduced, include the new module paths in the compile check.

## Risks and Mitigations

- Circular imports:
  - Keep shared constants and pure helpers in leaf modules.
  - Avoid importing the FastAPI app object from feature modules.
- Hidden behavior changes:
  - Move code before changing it.
  - Run the regression suite after every phase.
- Session compatibility:
  - Preserve persisted session schema unless an explicit migration is planned.
- Route drift:
  - Keep existing endpoint paths unchanged during the refactor.
- Over-extraction:
  - Do not create abstractions just to make the file tree look tidy. Extract around responsibilities that already exist.

## Done Criteria

The refactor is complete when:

- `main.py` is primarily app setup and router composition.
- Exposure interpretation logic lives under `exposure/*`.
- Data Hub client and capability logic lives under `data_hub/*`.
- Existing exposure API paths and UI behavior are preserved.
- The exposure interpretation regression suite passes.
- New modules are easy to test without starting the full application.
