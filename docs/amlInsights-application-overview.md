# amlInsights Application and Workspace Overview

**Review date:** August 10, 2026  
**Scope:** `amlInsights`, `amlredflags`, and `amlInsightsDataHub` active repositories

## Executive summary

The amlInsights workspace is an emerging, multi-tenant anti-money-laundering platform composed of three cooperating FastAPI applications. Together they cover two complementary AML activities: maintaining a governed catalog of red-flag guidance and investigating customers, accounts, counterparties, transactions, and external-risk relationships.

`amlInsights` is the platform shell and principal application. It owns login, users, tenants, roles, module entitlements, workflow configuration, audit records, red-flag selection and approval, operational reporting, and the investigator-facing entity and exposure search screens. It renders the web UI with Jinja templates and exposes the browser-facing APIs. In practical terms, users should enter the platform through this application.

`amlredflags` is a specialized content acquisition service. It retrieves documents from configured public or industry sources, uses an OpenAI model to extract candidate AML red flags, normalizes categories and product/service tags, and stores the resulting source-backed catalog. It also exposes health, batch-control, and catalog APIs. Earlier platform responsibilities still represented in some of its models have moved to `amlInsights`; the old platform endpoints now explicitly return HTTP 410 responses directing clients to `amlInsights`.

`amlInsightsDataHub` is a standalone ingestion, data-quality, analytical, and graph service for customer and transaction-monitoring data. It loads table-specific CSV feeds into a dimensional model, records operational and data-quality results, constructs a directed entity graph, and exposes APIs for customer search, graph expansion, exposure analysis, and transaction retrieval. `amlInsights` connects to a tenant's Data Hub over HTTP and presents those results in its own authenticated UI.

At a high level, the platform operates as follows:

```text
Public/industry sources                         Tenant AML data files
          |                                               |
          v                                               v
   amlredflags                                     amlInsightsDataHub
 fetch + AI extraction                       ingest + validate + model
          |                                               |
          v                                               v
 source-backed catalog                         graph and transaction APIs
          |                                               |
          +------------------+     +----------------------+
                             v     v
                            amlInsights
             identity, tenancy, workflows, audit, UI
                  red-flag governance + investigation
                             |
                             v
                     AML platform users
```

## What the application does

### Platform, identity, and governance

amlInsights provides the common platform services around the AML modules. Users authenticate with an email and password, receive a server-side session, and operate in a tenant context. The application distinguishes platform administration from tenant-scoped roles and uses both role checks and module entitlements to control features. Supported module codes include red flags, transaction monitoring, operational reporting, KYC, sanctions, and training, although the repository's most developed functional areas are red flags and investigation/exposure search.

Platform administrators can create and maintain tenants, assign module entitlements, manage tenant Data Hub connection settings, and define versioned workflows. Tenant administrators can maintain tenant users, role assignments, and business units. Important activities are written to an operational audit-event table, giving the application a foundation for traceability and control reporting.

The workflow subsystem is generic rather than hard-coded to one screen. It stores definitions, versions, states, allowed transitions, transition roles, tenant bindings, and executed workflow events. Draft workflows can be created, validated, published, and rolled back. The red-flag selection process uses this engine to govern actions such as submission, approval, rejection, and return.

### Red-flag catalog and tenant selection workflow

The red-flags capability starts with an institution-independent catalog of source documents and extracted red flags. Each catalog item retains its source, category, severity, descriptive text, confidence score, and normalized product and service tags. Synonyms map inconsistent raw model output to controlled canonical terms. amlInsights provides administrative curation screens and APIs for maintaining catalog entries and synonym mappings.

Tenant users search and filter this catalog, optionally use a catalog-constrained assistant to rank or explain relevant entries, and select applicable flags for their institution or business unit. Tenant-specific records separate a customer's adopted or customized content from the shared source catalog. The workspace then applies role-based workflow controls, preserves selection history, and exposes audit trails and approval queues. Custom tenant red flags can also be created when the shared catalog does not cover a local requirement.

This division is important: `amlredflags` discovers and extracts candidate knowledge, while `amlInsights` turns that knowledge into governed, tenant-specific decisions. The assistant in amlInsights is intended to remain grounded in the catalog rather than invent new regulatory content.

### Entity, network, and exposure investigation

The investigation experience is delivered by amlInsights but powered by Data Hub APIs. An authorized investigator can search for customer, account, or counterparty seeds and render the returned network using Cytoscape.js. The Data Hub uses NetworkX to construct a directed multigraph from current dimensional and bridge records. Core relationships include households to customers, customers to accounts and associated parties, Panama Papers relationships, and aggregated account-to-counterparty transaction flows.

The graph can add inferred name and address signature nodes for deterministic entity linkage and potential OFAC SDN matches. Transaction-flow edges summarize amount, count, date range, direction, and transaction types. Investigators can expand neighboring nodes, retrieve customer or exposure transactions, and filter transactions by jurisdiction, customer or branch geography, account properties, business unit, direction, AML classification, or mechanism.

The Exposure Search screen adds a natural-language interpretation layer in amlInsights. It classifies a question, resolves country aliases, maps the request to filters advertised by the connected Data Hub, constructs a query plan, and combines graph and transaction evidence into a response. OpenAI-assisted routing and interpretation are optional; deterministic configuration and capability discovery provide fallbacks and constrain what may be queried. Conversation sessions, messages, query interpretations, filter mappings, and response payloads are persisted so an investigator can review or continue earlier work.

## How the three repositories integrate

### amlInsights and amlredflags: database-centered catalog integration

The red-flags integration is primarily database-centered. Both applications use SQLAlchemy and Alembic and can be pointed at the same SQLite file locally or the same PostgreSQL database in deployment. The active amlInsights schema uses prefixed table names to make ownership clear: shared red-flag catalog tables use `srf_` prefixes, tenant-specific records use `trf_`, workflow tables use `wf_`, authentication tables use `auth_`, tenant tables use `ten_`, and operational tables use `ops_`.

Conceptually, amlredflags populates the source-document and red-flag catalog that amlInsights reads and governs. Both repositories include migrations and models reflecting the catalog's evolution, including raw and normalized categories/tags and synonyms. Care is therefore required when deploying migrations: database URL and PostgreSQL schema settings must agree, and each repository's migrations must be applied in the intended order. The amlInsights repository includes a helper for migrating both applications against a shared local database.

amlredflags also exposes catalog APIs, but the current amlInsights implementation queries its own platform database models rather than calling the red-flags service for normal user workflows. Its direct service API remains useful for batch triggering, batch status, health monitoring, catalog inspection, and operational separation. The architectural direction is explicit in code: platform auth, RBAC, tenant, and workflow APIs have been removed from amlredflags and centralized under `/api/platform/*` in amlInsights.

### amlInsights and Data Hub: tenant-specific HTTP API integration

The Data Hub integration is service-oriented rather than based on shared ORM tables. amlInsights stores one active Data Hub connection per tenant, including base URL, authentication mode, timeouts, status, and last connection-test result. Supported request authentication modes are none, bearer token, API key, and a custom header. Platform administrators configure and test this connection; investigator requests are authorized in amlInsights and then proxied to the selected tenant's Data Hub.

The proxy maps browser-facing `/api/entity-search/*` calls to Data Hub `/api/graph/*` endpoints. Examples include customer and exposure seed search, customer or seed-centered graph expansion, neighboring-node retrieval, and customer, seeded-exposure, or global transaction searches. This arrangement keeps tenant identity and application authorization in amlInsights while allowing each tenant to have a separate Data Hub deployment and dataset.

Data Hub advertises its supported graph and transaction features through `/api/graph/capabilities`. amlInsights uses this contract to determine available seed node types, filters, and global or seeded transaction operations. This is particularly important for natural-language exposure questions: the UI application should only build filters supported by the tenant's connected Data Hub. The graph responses follow a Cytoscape-compatible element format, making the handoff from NetworkX analytics to browser visualization relatively direct.

### Data ownership and request flow

The resulting ownership boundary is:

| Concern | System of record | Integration path |
|---|---|---|
| Users, tenants, roles, entitlements | amlInsights database | Internal application services |
| Workflow definitions and events | amlInsights database | Internal APIs and UI |
| Shared and tenant red-flag governance | Shared platform database, surfaced by amlInsights | amlredflags writes catalog data; amlInsights reads and governs it |
| Source acquisition and AI extraction runs | amlredflags database/schema | Batch and monitoring APIs; shared catalog tables |
| Customer, account, counterparty, and transaction data | amlInsightsDataHub database | Tenant-specific HTTP APIs |
| Data-quality and ingestion operations | amlInsightsDataHub database | Data Hub monitoring APIs/UI |
| Exposure conversations and interpretations | amlInsights database | amlInsights calls Data Hub and persists investigation context |

A typical red-flag flow is: trigger an amlredflags batch; fetch source documents; extract and normalize flags; persist catalog rows; curate the catalog in amlInsights; allow a tenant analyst to select flags; and route those selections through a versioned approval workflow.

A typical investigation flow is: ingest tenant CSV files in Data Hub; validate and load dimensions, bridges, and transactions; configure the tenant's Data Hub URL in amlInsights; search for a seed or ask an exposure question; authorize and proxy the request; build/query the graph in Data Hub; and render graph and transaction evidence in amlInsights while retaining the session history.

## Data Hub processing model

Data Hub accepts separately named CSV files for dimensions, bridges, and the cash transaction fact. It loads dependencies in that order and rejects unsupported filenames or rows that fail referential-integrity checks. Dimensions use a Type-2 history pattern keyed by business key plus `valid_from`; most graph operations select current records. Non-key attributes are held in `attr_json` and validated against per-dimension JSON schemas.

Data-quality rules and lists of values are configuration-driven and synchronized into database tables. Rule severities distinguish informative results from rejected records. Every job records files seen and processed, records read, loaded, and rejected, per-file statistics, and individual DQ outcomes. Reference-data scripts can refresh ISO country and currency data, OFAC SDN records, and Panama Papers nodes and relationships.

The initial analytical store is deliberately conventional: dimensions for household, customer, associated party, account, sub-account, branch, country, currency, counterparty account, transaction type, OFAC, and Panama entities; bridges for their relationships; and a cash/transaction fact. The graph is presently built at runtime rather than persisted in a dedicated graph database.

## Current architecture assessment

The workspace has a coherent target shape, but it is still closer to an actively evolving platform than a finished product. Its strongest design choices are the separation of platform governance from data processing, tenant-specific Data Hub connections, explicit workflow/audit models, catalog lineage back to sources, capability-based query planning, and configuration-driven data quality.

Several points deserve attention during the next review cycle:

- The top-level amlInsights README still describes a small “Hello World” application and materially understates the implemented platform. Repository documentation should be consolidated around the current architecture.
- `main.py` in amlInsights is very large and contains platform administration, catalog, workflow, investigation, proxy, and AI interpretation logic. The existing refactor plan correctly identifies modularization as an engineering priority.
- The red-flags database boundary is transitional. amlredflags retains legacy platform models and migrations even though its platform endpoints are retired, while amlInsights owns the newer prefixed platform schema. A single migration owner and an explicit catalog publication contract would reduce deployment risk.
- Data Hub's monitoring and graph endpoints currently have no application-level authentication of their own. Network isolation or a configured header/token is therefore important, especially outside local development.
- Data Hub connection secrets are represented as `auth_secret_ref`, but the current request code uses that stored value directly as the credential. Production deployment should clarify whether this field is a true secret-manager reference or encrypted secret storage.
- The amlInsights UI loads Cytoscape.js from a public CDN, which should be reviewed for production availability, content-security-policy, and software-supply-chain requirements.
- Natural-language investigation is thoughtfully constrained, but it remains a high-impact interpretation layer. Regression cases, country resolution, capability negotiation, query-plan logging, and user-visible evidence should remain part of release validation.

In summary, amlInsights is becoming the governed experience and control plane for a broader AML platform. amlredflags supplies curated, source-backed AML knowledge; amlInsightsDataHub supplies tenant-specific entity and transaction evidence; and amlInsights applies identity, tenancy, workflow, audit, AI-assisted interpretation, and visualization to turn those inputs into usable compliance workflows.
