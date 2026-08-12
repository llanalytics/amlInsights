# Engineering Backlog

## Purpose

This backlog tracks durable product and engineering work that should survive across sessions.

Use `docs/application_state_reset.md` for day-to-day handoff notes and current state. Use this backlog for work that should remain visible until it is completed, deferred, or intentionally removed.

## Status Legend

- `Proposed`: Worth considering, not yet committed for immediate work.
- `Ready`: Clear enough to pick up.
- `In Progress`: Currently being worked.
- `Done`: Completed and verified.
- `Deferred`: Intentionally postponed.

## Backlog Items

### Main Module Refactor

- Status: `Proposed`
- Plan: `docs/main_module_refactor_plan.md`
- Problem:
  - `main.py` now contains app setup, exposure interpretation, Data Hub access, session handling, graph enrichment, red flags routes, platform routes, and UI routes.
- Desired outcome:
  - Split `main.py` into logical modules without changing public API paths or current behavior.
- Acceptance criteria:
  - Exposure interpretation regression suite passes.
  - Route paths remain stable.
  - `main.py` becomes primarily app setup and router composition.

### Exposure Context UX

- Status: `Proposed`
- Problem:
  - Follow-up context can be powerful, but users need clearer visibility into when prior filters or subjects were inherited.
- Desired outcome:
  - The exposure UI shows whether a question was treated as standalone or follow-up.
  - The UI displays inherited filters when they are used.
  - Users can explicitly clear context or ask a question as new.
- Acceptance criteria:
  - Analysts can tell why a prior country, direction, mechanism, or subject was applied.
  - Regression cases cover context inheritance and context suppression.

### CI Execution With Fixture Data Hub Services

- Status: `Ready`
- Problem:
  - The regression suite currently runs well locally, but automated CI needs reliable fixture services.
  - Interpretation quality can regress quietly unless the exposure regression suite runs automatically against known data.
- Desired outcome:
  - CI starts a fixture `amlInsightsDataHub` service loaded with deterministic sample data.
  - CI starts `amlInsights` pointed at that fixture Data Hub service.
  - CI runs the exposure interpretation regression suite against the fixture environment.
- Fixture data scope:
  - Use the checked-in `amlInsightsDataHub/data/sample/` files as the baseline fixture set.
  - Seed enough tenant/user/configuration state for `amlInsights` to call the Data Hub service using the same local workflow as `scripts/check_local_exposure_apps.sh`.
  - Keep fixture data stable so case expectations do not drift unexpectedly.
- Candidate implementation:
  - Add a CI workflow that installs both applications.
  - Initialize or migrate both local databases.
  - Load Data Hub sample data.
  - Start `amlInsightsDataHub` on `127.0.0.1:8100`.
  - Start `amlInsights` on `127.0.0.1:8000`.
  - Run `./scripts/check_local_exposure_apps.sh`.
  - Run `./scripts/run_exposure_interpretation_regression.sh`.
- Acceptance criteria:
  - CI can run the same regression command used locally.
  - Test data is deterministic.
  - Failures show which case and assertion changed.
  - The current exposure suite passes in CI with no manual services running.
  - CI logs include enough server output to debug startup, connection, and regression failures.

### Interpretation Lab UI

- Status: `Proposed`
- Problem:
  - Fine-tuning interpretation currently happens through manual questions and JSON inspection.
- Desired outcome:
  - A developer-facing screen for entering a question, inspecting intent/filter/query-plan output, marking correctness, and exporting a regression case.
- Acceptance criteria:
  - New regression cases can be generated from analyst feedback with minimal hand editing.
  - The lab shows applied filters, dropped filters, inherited context, and executed query steps.

### Distinct Counterparty Result Capability

- Status: `Proposed`
- Problem:
  - Some questions ask for counterparties, but the current transaction-backed flow often returns transaction rows rather than a distinct counterparty result set.
- Desired outcome:
  - Add a counterparty result capability that can return distinct counterparties matching country, jurisdiction, transaction, or graph nexus filters.
- Acceptance criteria:
  - Questions like `show me counterparties that have a Russian nexus` can return counterparties directly.
  - Transaction evidence remains available when relevant.

### Data Hub Counterparty Graph Aggregation

- Status: `Ready`
- Problem:
  - The current counterparty aggregation behavior is prototyped in `amlInsights`.
  - Data Hub still builds and returns large counterparty-heavy graph payloads before `amlInsights` prunes them.
  - This increases traffic between `amlInsightsDataHub` and `amlInsights` and splits graph semantics across two applications.
- Desired outcome:
  - Move counterparty aggregation/collapse behavior into `amlInsightsDataHub` graph endpoints.
  - Keep `amlInsights` responsible for rendering and user interaction, not graph semantic pruning.
- Current prototype behavior to preserve:
  - Show the top 4 counterparties by transaction amount in the initial exposure graph.
  - Exclude `CounterpartyAccount:NA` from enrichment seed selection.
  - Replace non-top counterparties with a `CounterpartyRemainder` aggregate node.
  - Connect the aggregate node to relevant account/customer anchors.
  - Avoid orphan name/address surrogate nodes in the initial graph.
  - Expand the aggregate node into real counterparty nodes without automatically expanding high-degree surrogate/name neighborhoods.
- Candidate implementation:
  - Add optional Data Hub graph parameters such as `counterparty_limit=4` and `aggregate_counterparties=true`.
  - Have `/api/graph/exposure` return top counterparty nodes, aggregate metadata, and expansion hints.
  - Add or extend an expansion endpoint so the aggregate node can retrieve hidden counterparties on demand.
  - Keep response metadata explicit, including hidden counterparty count, selected counterparty IDs, and ranking basis.
- Acceptance criteria:
  - Network payload from Data Hub to `amlInsights` is reduced for counterparty-heavy graphs.
  - UI behavior remains at least as usable as the current prototype.
  - Existing exposure interpretation regression suite passes.
  - Add focused graph tests or fixture assertions for aggregate node creation, expansion metadata, and `NA` seed exclusion.

### External Negative News Integration

- Status: `Proposed`
- Problem:
  - The current negative-news behavior is graph/evidence constrained and does not retrieve external news.
- Desired outcome:
  - Define whether negative news should remain graph-only or connect to curated/adjudicated external news sources.
- Acceptance criteria:
  - The product clearly distinguishes graph indicators, sanctions indicators, Panama/offshore indicators, and true external adverse media.

### Data Hub Capability Catalog Hardening

- Status: `Proposed`
- Problem:
  - The capability catalog is now central to interpretation, so regressions in capability metadata could break query planning.
- Desired outcome:
  - Add tests around Data Hub capability catalog content and compatibility with `amlInsights` filter mapping.
- Acceptance criteria:
  - Capability catalog changes are verified before interpretation behavior changes.
  - Unsupported filters are dropped and reported consistently.

### Country Alias Governance

- Status: `Proposed`
- Problem:
  - `config/country_aliases.json` is useful, but country names, abbreviations, and informal aliases need ongoing governance.
- Desired outcome:
  - Establish a process for adding country aliases and regression cases when analysts encounter misses.
- Acceptance criteria:
  - Common names like `Russia`, `China`, `UK`, `UAE`, and variants resolve predictably.
  - New aliases are covered by unit tests or interpretation regression cases.

### Repository Hygiene

- Status: `Proposed`
- Problem:
  - Generated local files such as `.DS_Store` can appear as untracked changes.
- Desired outcome:
  - Add ignore rules or cleanup practices so local artifacts do not clutter reviews.
- Acceptance criteria:
  - Generated OS files are ignored.
  - Git status stays focused on intentional application changes.

## Adding Items

When adding an item, include:

- Status.
- Problem.
- Desired outcome.
- Acceptance criteria.
- Link to a plan or implementation doc when one exists.
