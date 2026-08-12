# Exposure Interpretation Regression Cases

This directory stores file-based regression cases for the exposure-question interpreter.

The goal is to make analyst interpretation behavior durable and reviewable as Data Hub capabilities, graph data, and natural-language rules evolve.

## Structure

```text
tests/exposure_interpretation/
  README.md
  case_schema.json
  cases/
    france_transactions.json
    outside_us_clarification.json
    followup_expansion.json
    entity_scoped_exposure.json
```

## Case File Shape

Each case file contains:

- `schema_version`: case file schema version.
- `description`: human-readable purpose.
- `cases`: list of regression cases.

Each case contains:

- `name`: stable test identifier.
- `tenant_id`: tenant to use when running locally.
- `create_session`: whether the runner should create a fresh exposure session.
- `turns`: ordered analyst questions and expectations.

Each turn contains:

- `question`: analyst question sent to `/api/entity-search/exposure-question`.
- `filter_overrides`: optional structured overrides, used for clarification choices.
- `expect`: assertions the runner should evaluate.

Important expectation fields:

- `mode`: expected response mode, when relevant.
- `status`: expected response status, when relevant.
- `queried_steps`: ordered `queried_data[].step` values that must appear in sequence. Extra repeated steps are allowed.
- `must_not_query_steps`: steps that must not appear.
- `plan_endpoints`: expected ordered `structured_query_plan.steps[].endpoint` values that must appear in sequence, excluding missing endpoints.
- `filters`: expected `transaction_filter_mapping.applied_filters` values. Use `null` when a filter must be absent/null.
- `min_tx_rows` / `max_tx_rows`: transaction evidence row count bounds.
- `sample_transaction_keys`: transaction keys expected in sampled transaction rows.
- `clarification_required`: whether `clarification` should be present.
- `clarification_labels`: labels expected in returned clarification choices.
- `min_enriched_transaction_nodes`: minimum number of transaction-linked nodes used to enrich the graph.
- `min_graph_nodes`: minimum rendered graph node count when `include_graph` is enabled for the turn.

## Running Locally

Start `amlInsights` and `amlInsightsDataHub`, then run:

```bash
.venv/bin/python -m tests.exposure_interpretation.runner --base-url http://127.0.0.1:8000
```

The runner exits non-zero when any turn fails and prints the failed case, turn, question, and assertion messages.
