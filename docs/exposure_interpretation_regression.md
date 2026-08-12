# Exposure Interpretation Regression Workflow

## Purpose

This workflow makes exposure-question interpretation tuning repeatable.

Use it whenever a change touches:

- exposure intent routing
- transaction filter interpretation
- country alias configuration or country dimension data
- follow-up resolution
- Data Hub graph or transaction capabilities
- exposure question UI behavior that depends on interpreted results
- sample Data Hub data that affects graph or transaction responses

The goal is simple: before and after an interpretation change, run the same local regression suite and confirm expected analyst behavior still holds.

## Local Services

The regression runner expects both local apps to be running:

```text
amlInsights:        http://127.0.0.1:8000
amlInsightsDataHub: http://127.0.0.1:8100
```

Start Data Hub from the `amlInsightsDataHub` repo:

```bash
cd ../amlInsightsDataHub
PORT=8100 ./scripts/start_server.sh
```

Start `amlInsights` from this repo:

```bash
./scripts/start_local.sh app.db 8000
```

If a different port is needed, set the matching environment variable before running the health check or regression wrapper.

## Health Check

From the `amlInsights` repo:

```bash
./scripts/check_local_exposure_apps.sh
```

The script checks:

- `amlInsights` `/health`
- `amlInsightsDataHub` `/health`
- `amlInsightsDataHub` `/api/graph/capabilities`

Expected output:

```text
OK   amlInsights health: http://127.0.0.1:8000/health
OK   amlInsightsDataHub health: http://127.0.0.1:8100/health
OK   amlInsightsDataHub capabilities: http://127.0.0.1:8100/api/graph/capabilities
Local exposure apps are reachable.
```

Override URLs when needed:

```bash
AML_INSIGHTS_BASE_URL=http://127.0.0.1:8001 \
DATA_HUB_BASE_URL=http://127.0.0.1:8101 \
./scripts/check_local_exposure_apps.sh
```

## Run the Full Regression Suite

From the `amlInsights` repo:

```bash
./scripts/run_exposure_interpretation_regression.sh
```

The script:

1. Runs the local service health check.
2. Executes `tests.exposure_interpretation.runner`.
3. Exits non-zero if any case fails.

Current expected result:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

## Run a Single Case Group

Use the runner's `--case` filter to run cases whose names contain a substring:

```bash
./scripts/run_exposure_interpretation_regression.sh --case france
```

Examples:

```bash
./scripts/run_exposure_interpretation_regression.sh --case outside_us
./scripts/run_exposure_interpretation_regression.sh --case arigato
./scripts/run_exposure_interpretation_regression.sh --case followup
```

## Useful Environment Variables

```text
AML_INSIGHTS_BASE_URL   amlInsights base URL. Default: http://127.0.0.1:8000
DATA_HUB_BASE_URL       Data Hub base URL for health checks. Default: http://127.0.0.1:8100
AML_USER_EMAIL          User email header for regression API calls. Default: investigator@tenant1.com
PYTHON_BIN              Python executable for the runner. Default: .venv/bin/python
SKIP_HEALTH_CHECK       Set to 1 to run the regression suite without preflight health checks.
```

Example:

```bash
AML_INSIGHTS_BASE_URL=http://127.0.0.1:8001 \
DATA_HUB_BASE_URL=http://127.0.0.1:8101 \
AML_USER_EMAIL=investigator@tenant1.com \
./scripts/run_exposure_interpretation_regression.sh
```

## Case Files

Regression cases live under:

```text
tests/exposure_interpretation/cases/
```

Current case groups:

```text
entity_scoped_exposure.json
followup_context_boundaries.json
followup_expansion.json
france_transactions.json
france_transaction_variants.json
outside_us_clarification.json
outside_us_dimension_hints.json
russia_transactions.json
```

Each case file contains:

- `schema_version`
- `description`
- `cases`

Each case contains:

- `name`
- `description`
- `tenant_id`
- `create_session`
- `turns`

Each turn contains:

- `question`
- optional `filter_overrides`
- `expect`

## Adding a Case

1. Choose the closest existing case file or create a new one under `tests/exposure_interpretation/cases/`.
2. Add a stable case `name`.
3. Use the analyst question exactly as posed when possible.
4. Assert the behavior that matters:
   - `scope`
   - `queried_steps`
   - `must_not_query_steps`
   - `plan_endpoints`
   - `filters`
   - `min_tx_rows` or `max_tx_rows` only when row count is part of the contract
   - `sample_transaction_keys` only when a specific fixture row must be preserved
   - `clarification_required`
   - `clarification_labels`
5. Run the focused case.
6. Run the full suite.

Prefer durable assertions over overly exact assertions. For example, use minimum row counts when the fixture could grow, and use `must_not_query_steps` to protect against unwanted seed search for global transaction questions.

## Troubleshooting

### Health Check Fails

Confirm both apps are running on the expected ports:

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8100/health
curl -fsS http://127.0.0.1:8100/api/graph/capabilities
```

If ports differ, set `AML_INSIGHTS_BASE_URL` and `DATA_HUB_BASE_URL`.

### A Global Transaction Case Runs Seed Search

Look at:

- intent routing
- `_is_global_transaction_aggregate_question`
- deterministic filter mapping
- structured query plan endpoint

Global, subjectless transaction cases should usually include:

```text
must_not_query_steps: ["seed_search", "graph_expansion", "transaction_details"]
```

### An Entity-Scoped Exposure Case Becomes Global

Look at subject detection and routing safeguards. Entity-scoped questions such as `Show exposure for ARIGATO LIMITED ...` should stay seed-backed even when they include transaction-like wording.

### A Filter Is Missing

Check:

- deterministic transaction filter mapping
- `config/country_aliases.json`
- `country_resolution.py`
- Data Hub capabilities and supported filters
- transaction filter catalog vocabularies
- `transaction_filter_mapping.dropped_unsupported_filters`

### A Follow-Up Inherits Stale Filters

Check:

- session history
- `_followup_filter_overrides`
- expected cleanup of mechanism, direction, and geography filters

## Current Baseline

As of 2026-04-28, the local suite passes:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```
