# Data Hub Capabilities and Interpretation Regression Plan

## Goal

Build a scalable foundation for exposure-question interpretation so new Data Hub data, graph entities, filters, and analyst question patterns can be added without fragile one-off fixes.

The core design principle:

- `amlInsightsDataHub` declares what it can answer.
- `amlInsights` interprets analyst language against those declared capabilities.
- Regression tests protect interpretation behavior as the data model and graph expand.

## Phase 1: Data Hub Capabilities Catalog

Purpose: make Data Hub expose machine-readable metadata about its graph, transaction search, and filter capabilities.

Status:

- Started 2026-04-28.
- Initial endpoint and catalog builder implemented in `amlInsightsDataHub`.
- Next Phase 1 hardening step: add formal tests once a Data Hub test structure is introduced.

Deliverables:

- Add `amlInsightsDataHub/app/capability_catalog.py`.
- Add endpoint:

```text
GET /api/graph/capabilities
```

Initial catalog should include:

- graph node types
- graph edge types
- searchable seed node types
- global transaction search support
- seeded transaction search support
- supported transaction filters
- dimension vocabularies
- source table/field metadata for filters

Example response shape:

```json
{
  "version": "2026-04-28.v1",
  "node_types": ["Customer", "Account", "CounterpartyAccount", "Branch"],
  "edge_types": ["OWNS_ACCOUNT", "TXN_FLOW", "SHARES_SURROGATE"],
  "global_transaction_search": {
    "supported": true,
    "endpoint": "/api/graph/exposure/transactions/global",
    "filters": {
      "direction": ["Inbound", "Outbound"],
      "mechanism_contains": true,
      "counterparty_jurisdiction": ["FR", "US", "PA"],
      "outside_country_code_2": ["US", "FR", "PA"]
    }
  },
  "seeded_transaction_search": {
    "supported": true,
    "endpoint": "/api/graph/exposure/transactions",
    "seed_node_types": ["Customer", "Account", "CounterpartyAccount"]
  },
  "dimensions": {
    "counterparty_jurisdiction": {
      "source": "dh_dim_counterparty_account",
      "field": "jurisdiction"
    },
    "transaction_country": {
      "source": "dh_fact_cash",
      "field": "country_code_2"
    }
  }
}
```

Verification:

- Endpoint returns JSON.
- Catalog values match actual local Data Hub fixture data.
- Existing `/api/graph/transaction-filter-catalog` can remain separate initially, but the broader capabilities endpoint should either reference or include those vocabularies.

## Phase 2: amlInsights Capability Client

Purpose: let `amlInsights` interpret questions based on actual Data Hub capabilities instead of hardcoded assumptions.

Status:

- Started 2026-04-28.
- Initial capability client helpers are wired into `amlInsights/main.py`.
- Transaction filter normalization now prefers `/api/graph/capabilities` vocabularies and falls back to `/api/graph/transaction-filter-catalog` when capabilities are unavailable.
- Transaction mapping audit now includes the Data Hub capability version, supported filter list, and unsupported-filter drops.
- Next Phase 2 hardening step: expand capability usage beyond transaction filters into broader graph/intent planning as new Data Hub domains are added.

Deliverables:

- Add helper functions in `amlInsights`, initially in `main.py` or a small dedicated module:

```text
_get_data_hub_capabilities(connection)
_capability_supports_filter(capabilities, filter_name)
_capability_supports_global_transactions(capabilities)
_capability_seed_node_types(capabilities)
```

Use capabilities in:

- transaction filter normalization
- global vs seed-scoped decisioning
- ambiguity detection
- query plan generation
- structured query plan display

Verification:

- Current France and outside-US behavior still passes.
- If a capability is absent, `amlInsights` does not emit unsupported filters.
- Structured query plans reflect supported Data Hub endpoints and filters.

## Phase 3: Regression Case Format

Purpose: encode interpretation expectations as durable, reviewable test cases.

Status:

- Started 2026-04-28.
- Added initial case directory, README, schema file, and seed case files under `tests/exposure_interpretation/`.
- JSON parse validation completed for the schema and all case files.
- Next Phase 3 hardening step: let the Phase 4 runner enforce the schema and report unsupported expectation fields clearly.

Deliverables:

- Add directory:

```text
tests/exposure_interpretation/cases/
```

- Define JSON case schema supporting:
  - single-turn questions
  - multi-turn session flows
  - expected filters
  - expected queried steps
  - expected plan endpoint
  - expected global vs seed-scoped behavior
  - expected min/max rows or transaction IDs

Example case:

```json
{
  "name": "expand_france_wire_to_any_counterparty_transaction",
  "tenant_id": 1,
  "session": [
    {
      "question": "find wires to france",
      "expect": {
        "queried_steps": ["transaction_filter_mapping", "global_transaction_details"],
        "filters": {
          "direction": "Outbound",
          "mechanism_contains": "Wire",
          "counterparty_jurisdiction": "FR",
          "outside_country_code_2": null
        },
        "min_tx_rows": 1
      }
    },
    {
      "question": "lets expand this search to any transaction with a counterparty in France",
      "expect": {
        "queried_steps": ["transaction_filter_mapping", "global_transaction_details"],
        "filters": {
          "direction": null,
          "mechanism_contains": null,
          "counterparty_jurisdiction": "FR"
        },
        "min_tx_rows": 4
      }
    }
  ]
}
```

Recommended case groups:

- `france_transactions.json`
- `outside_us_clarification.json`
- `followup_expansion.json`
- `entity_scoped_exposure.json`

## Phase 4: Local Regression Runner

Purpose: run interpretation tests against local `amlInsights` and Data Hub services.

Status:

- Started 2026-04-28.
- Added stdlib-only runner in `tests/exposure_interpretation/runner.py`.
- Runner executes all case files against a local `amlInsights` base URL, creates temporary exposure sessions, sends each turn to `/api/entity-search/exposure-question`, and checks filters, queried steps, plan endpoints, transaction evidence, sample transaction IDs, clarification labels, and scope.
- Runner assertions use ordered subsequences for queried steps/endpoints so repeated graph expansions do not create brittle failures.
- Initial local verification passed:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000
```

Result:

```text
Exposure interpretation regression: 9/9 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

Implementation note:

- Phase 4 exposed a backend gap where explicit clarification `filter_overrides` and ambiguous outside-US graph/exposure questions did not always promote a graph-only query plan into transaction filter mapping. `amlInsights/main.py` now adds a transaction-details planning step for explicit structured filter overrides and ambiguous outside-US geography so clarification and transaction evidence paths run consistently.

Deliverables:

- Add:

```text
tests/exposure_interpretation/runner.py
```

Runner behavior:

- reads all case files
- creates temporary exposure sessions when needed
- posts questions to `/api/entity-search/exposure-question`
- checks:
  - `transaction_filter_mapping.applied_filters`
  - `queried_data[].step`
  - `structured_query_plan.steps`
  - `interpreted_query`
  - `transaction_evidence`
  - row counts or transaction IDs
- prints compact pass/fail output

Target command:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000
```

## Phase 5: Seed Regression Suite

Purpose: protect the interpretation behavior already tuned.

Status:

- Started 2026-04-28.
- Expanded the initial regression seed from 9 turns to 20 turns.
- Added France/global transaction wording variants:
  - `how many wires are there to France`
  - `find transactions to counterparties in France`
  - `find any transactions with a counterparty in France`
- Added Russia/global transaction wording:
  - `I am looking for transactions to Russia`
  - protects positive `counterparty_jurisdiction = RU` and prevents erroneous `outside_counterparty_jurisdiction = RU`
- Added follow-up context boundary coverage:
  - China transaction search followed by `show me counterparties that have a Russian nexus`
  - protects against stale China transaction filters limiting a new counterparty/nexus search
  - verifies a later `negative news linked to those counterparties` follow-up enriches the graph from transaction-linked nodes
- Added explicit outside-US dimension hint cases:
  - transaction country outside the US
  - counterparties outside the US
  - customer country outside the US
  - branch country outside the US
- Phase 5 exposed and fixed a routing issue: entity-scoped exposure questions that include transaction-like wording should remain seed-scoped rather than being converted into global transaction searches.
- Current local verification:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000
```

Result:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

Initial cases:

1. `find wires to france`
   - global transaction search
   - no seed search
   - `direction = Outbound`
   - `mechanism_contains = Wire`
   - `counterparty_jurisdiction = FR`

2. `lets expand this search to any transaction with a counterparty in France`
   - follow-up
   - global transaction search
   - no seed search
   - clears wire
   - clears direction
   - keeps `counterparty_jurisdiction = FR`

3. `I was looking for all transactions sent to counterparties in France`
   - global transaction search
   - `direction = Outbound`
   - `counterparty_jurisdiction = FR`
   - no `outside_country_code_2`

4. `Show exposure for ARIGATO LIMITED outside the US`
   - seed search
   - graph expansion
   - clarification required

5. Clarification choice: counterparty jurisdiction
   - applies `outside_counterparty_jurisdiction = US`
   - excludes US counterparty jurisdiction rows

6. `Switch outside US to transaction country instead`
   - follow-up
   - clears counterparty geography
   - applies `outside_country_code_2 = US`

## Phase 6: CI and Developer Workflow

Purpose: make interpretation tuning safe and repeatable.

Status:

- Started 2026-04-28.
- Added developer workflow documentation:
  - `docs/exposure_interpretation_regression.md`
- Added executable helper scripts:
  - `scripts/check_local_exposure_apps.sh`
  - `scripts/run_exposure_interpretation_regression.sh`
- Health-check script verifies:
  - `amlInsights` `/health`
  - `amlInsightsDataHub` `/health`
  - `amlInsightsDataHub` `/api/graph/capabilities`
- Regression wrapper runs health checks first, then executes the exposure interpretation runner.
- Verification completed:

```bash
bash -n scripts/check_local_exposure_apps.sh
bash -n scripts/run_exposure_interpretation_regression.sh
./scripts/check_local_exposure_apps.sh
./scripts/run_exposure_interpretation_regression.sh
```

Current wrapper result:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

Deliverables:

- Add docs:

```text
docs/exposure_interpretation_regression.md
```

Include:

- how to start local apps
- how to run regression suite
- how to add a new case
- expected output format
- troubleshooting common failures

Optional later:

- run suite in CI with local fixture DBs
- add a wrapper script, for example:

```bash
scripts/run_exposure_interpretation_regression.sh
```

## Phase 7: Interpretation Lab UI

Purpose: create an analyst/developer feedback loop after the file-based regression suite exists.

Possible route:

```text
/ui/exposure-interpretation-lab
```

Possible features:

- run a question
- choose prior context/session
- inspect filters and plan
- mark result correct/incorrect
- export or save a regression case
- run selected test cases

This should come after the file-based test suite so the UI uses the same durable case format rather than inventing a second workflow.

## Recommended Execution Order

1. Build `GET /api/graph/capabilities` in Data Hub.
2. Add a small `amlInsights` capability client.
3. Create the regression case schema.
4. Build the local regression runner.
5. Seed 10-15 cases from current tuning work.
6. Use the runner for every interpretation change.
7. Add the Interpretation Lab UI later.

## Open Design Questions

- Should `/api/graph/capabilities` fully replace `/api/graph/transaction-filter-catalog`, or should it include a link/reference to that endpoint?
- Should regression cases assert exact row counts or minimum row counts? Minimum counts are less brittle, but exact counts are better for fixture stability.
- Should the regression runner default to local running services, or should it optionally start the services itself?
- Should failed interpretation cases be saved as artifacts for review?
