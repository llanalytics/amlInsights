# Data Hub Capabilities and Interpretation Regression Implementation Results

## Summary

This document explains how the Data Hub capabilities and exposure interpretation regression plan was implemented, what behavior changed, and what the current verification results are.

The implementation established a scalable loop for tuning natural-language exposure questions:

- `amlInsightsDataHub` declares the graph and transaction capabilities it supports.
- `amlInsights` reads those capabilities before interpreting analyst questions.
- File-based regression cases protect the tuned interpretation behavior.
- A local runner executes the cases against the running applications.

Current result:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

## Why We Built This

The exposure capability had become powerful because of its question interpretation layer, but several issues showed that one-off tuning was not enough:

- Subjectless transaction questions such as `find wires to france` could accidentally trigger entity seed search.
- The phrase `to France` needed to map to counterparty jurisdiction for wire/payment questions, not transaction country.
- Country-name coverage needed to scale beyond a small hardcoded list in `main.py`.
- Follow-up questions could inherit stale filters like `outside_country_code_2 = US` or `mechanism_contains = Wire`.
- Ambiguous phrases such as `outside the US` needed structured clarification because several geography dimensions are possible.
- The UI and structured query plan needed to reflect what was actually executed.

The new implementation makes those behaviors explicit, testable, and easier to extend as more data is added to Data Hub and the graph.

## Implemented Architecture

### Data Hub Declares Capabilities

`amlInsightsDataHub` now exposes:

```text
GET /api/graph/capabilities
```

Implemented in:

```text
../amlInsightsDataHub/app/capability_catalog.py
../amlInsightsDataHub/app/main.py
```

The catalog includes:

- graph endpoints
- graph node types
- graph edge types
- seed-search node types
- global transaction search support
- seeded transaction search support
- supported transaction filters
- transaction vocabularies
- dimension source metadata

The current catalog version is:

```text
2026-04-28.v1
```

### amlInsights Reads Capabilities

`amlInsights/main.py` now fetches Data Hub capabilities for each exposure question and uses them when interpreting transaction filters and planning execution.

Important helper behavior:

- Reads `/api/graph/capabilities`.
- Falls back to `/api/graph/transaction-filter-catalog` if needed.
- Uses declared vocabularies for deterministic filter validation.
- Drops unsupported transaction filters.
- Uses declared global transaction support before routing to the global transaction endpoint.
- Uses declared seeded transaction node types when selecting transaction seeds.
- Adds capability metadata to the transaction filter mapping audit.

The transaction mapping audit now includes:

```text
data_hub_capabilities_version
supported_filters
dropped_unsupported_filters
```

## Key Behavior Changes

### Country Alias Resolution Moved to Configuration

Country name to ISO-2 resolution is no longer hardcoded in `main.py`.

Implemented in:

```text
country_resolution.py
config/country_aliases.json
```

The resolver:

- loads canonical country names and ISO codes from the configured Data Hub country dimension CSV
- layers manual analyst aliases from `config/country_aliases.json`
- includes fallback aliases for critical common names
- returns aliases longest-first so `russian federation` matches before `russia`, and `united states` matches before `us`

This fixed the Russia issue and makes future country-name expansion a configuration/data task instead of a code edit.

### Global Transaction Questions Skip Graph Seed Search

Subjectless transaction questions now run directly against global transaction search when appropriate.

Examples:

```text
find wires to france
how many wires are there to France
find transactions to counterparties in France
```

Expected behavior:

- runs `transaction_filter_mapping`
- runs `global_transaction_details`
- does not run `seed_search`
- does not run `graph_expansion`
- uses `/api/graph/exposure/transactions/global`

### France Counterparty Interpretation

France transaction wording now maps to counterparty jurisdiction when the analyst asks about wires/payments/transactions to France or counterparties in France.

Examples:

```text
find wires to france
I was looking for all transactions sent to counterparties in France
find any transactions with a counterparty in France
```

Expected filters include:

```text
counterparty_jurisdiction = FR
```

For wire questions:

```text
mechanism_contains = Wire
direction = Outbound
```

For broad transaction questions:

```text
mechanism_contains = null
direction = null
```

### Follow-Up Filter Cleanup

Follow-up expansion questions now clear stale filters when the new wording broadens the scope.

Example flow:

```text
1. find wires to france
2. lets expand this search to any transaction with a counterparty in France
```

Expected second-turn behavior:

- keeps `counterparty_jurisdiction = FR`
- clears `mechanism_contains`
- clears `direction`
- does not inherit `outside_country_code_2 = US`
- remains global and does not run entity seed search

### Outside-US Clarification

Ambiguous outside-US wording now asks the analyst which geography dimension should be used.

Example:

```text
Show exposure for ARIGATO LIMITED outside the US
```

Expected behavior:

- seed search runs for the entity
- graph expansion runs
- transaction filter mapping runs
- response pauses with `needs_clarification`
- clarification choices include:
  - Counterparty jurisdiction
  - Transaction country
  - Customer country
  - Branch country

When a clarification choice is provided through `filter_overrides`, the backend now promotes the graph-only plan into transaction details so the selected dimension is actually executed.

### Explicit Outside-US Dimension Hints

Questions that name a dimension should not ask for clarification.

Examples:

```text
Show exposure for ARIGATO LIMITED with transaction country outside the US
Show exposure for ARIGATO LIMITED with counterparties outside the US
Show exposure for ARIGATO LIMITED with customer country outside the US
Show exposure for ARIGATO LIMITED with branch country outside the US
```

Expected behavior:

- remains entity-scoped and seed-backed
- runs transaction filter mapping
- applies the requested outside-US dimension
- does not ask for clarification

This also fixed an important routing issue: entity-scoped exposure questions with transaction-like wording should not be converted into global transaction searches.

## Regression Test Implementation

Regression tests live under:

```text
tests/exposure_interpretation/
```

Important files:

```text
tests/exposure_interpretation/README.md
tests/exposure_interpretation/case_schema.json
tests/exposure_interpretation/runner.py
tests/exposure_interpretation/cases/entity_scoped_exposure.json
tests/exposure_interpretation/cases/followup_context_boundaries.json
tests/exposure_interpretation/cases/followup_expansion.json
tests/exposure_interpretation/cases/france_transactions.json
tests/exposure_interpretation/cases/france_transaction_variants.json
tests/exposure_interpretation/cases/outside_us_clarification.json
tests/exposure_interpretation/cases/outside_us_dimension_hints.json
tests/exposure_interpretation/cases/russia_transactions.json
```

The runner is intentionally stdlib-only. It:

- reads all JSON case files
- creates temporary exposure sessions when requested
- posts each turn to `/api/entity-search/exposure-question`
- applies optional `filter_overrides`
- checks response mode, status, and scope
- checks ordered queried steps
- checks forbidden queried steps
- checks structured plan endpoints
- checks applied transaction filters
- checks transaction row bounds when specified
- checks sampled transaction keys when specified
- checks clarification presence and labels
- prints compact pass/fail output

Run command:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000
```

Run one case by name substring:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --case france --base-url http://127.0.0.1:8000
```

## Current Seed Coverage

The current suite covers 20 turns across these behavior groups:

- global France wire questions
- count-style France wire questions
- France counterparty transaction questions
- Russia counterparty transaction questions
- session context boundaries between transaction searches and new counterparty/nexus searches
- graph enrichment from transaction-linked counterparties for follow-up negative-news questions
- broadening from wires to any transaction
- direct all-transactions-to-France wording
- entity-scoped ARIGATO exposure
- ambiguous outside-US clarification
- counterparty-jurisdiction clarification choice
- switching a follow-up from counterparty geography to transaction country
- explicit outside-US dimension hints for transaction, counterparty, customer, and branch geography

## Verification Results

Compilation checks:

```bash
.venv/bin/python -m py_compile main.py tests/exposure_interpretation/runner.py
```

Regression run:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000
```

Current output:

```text
Exposure interpretation regression: 20/20 turn(s) passed (0 failed turn(s), 0 assertion failure(s))
```

Data Hub capability endpoint was also smoke tested locally:

```text
GET http://127.0.0.1:8100/api/graph/capabilities
```

It returned capability version `2026-04-28.v1` with graph metadata, transaction capability metadata, supported filters, and live vocabularies.

## Files Changed

`amlInsightsDataHub`:

```text
../amlInsightsDataHub/app/capability_catalog.py
../amlInsightsDataHub/app/main.py
```

`amlInsights`:

```text
main.py
country_resolution.py
config/country_aliases.json
templates/exposure_search.html
docs/application_state_reset.md
docs/data_hub_capabilities_and_interpretation_regression_plan.md
docs/data_hub_capabilities_and_regression_implementation_results.md
tests/exposure_interpretation/
tests/test_country_resolution.py
```

## Remaining Work

Recommended next steps:

- Add new regression cases whenever analyst feedback reveals an interpretation issue.
- Use `docs/exposure_interpretation_regression.md` as the standard developer workflow for starting both local apps and running the suite.
- Use `scripts/check_local_exposure_apps.sh` to verify the local apps and Data Hub capability endpoint.
- Use `scripts/run_exposure_interpretation_regression.sh` as the standard local regression command.
- Later, consider CI execution with fixture Data Hub services.
- Later, build an Interpretation Lab UI that can export analyst feedback into the same JSON case format.
