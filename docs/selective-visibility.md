# Opt-in project file metadata visibility

`PROJECT_VISIBILITY_ENABLED` defaults to false. Existing commons continue to
serve IndexD metadata publicly without an Arborist lookup or new policy grants.
Set the flag to true in IndexD's config or environment to enforce the independent
`indexd/read-metadata` action on **every** resource in the record's existing `authz`.
There is no new record visibility field, database column, or visibility migration.

Grants belong in standard users YAML roles, policies and groups. Storage remains
an independent `fence/read-storage` permission. `/open` is an explicit metadata
grant too; unscoped/empty-AuthZ records are hidden from ordinary callers when
opted in. Inventory and classify legacy unscoped records before enabling.

Both relational backends filter before paging, projections, counts and stats.
Record aliases, versions, URL searches, DRS/bundles and mutation existence checks
use the same authorization. Validated Basic service credentials and IndexD
administrators remain trusted. Background indexing code without a request context
retains complete access. Arborist outages fail closed; invalid caller grants do
not become public access. Browser cookies and Bearer tokens are supported.

New versions inherit omitted AuthZ only in opted-in mode. Clearing AuthZ makes a
record undiscoverable rather than public. The original API and legacy behavior
remain available with the opt-in disabled. Disabling the flag intentionally
restores public metadata and is not a privacy-preserving rollback.

This service does not filter separate Elasticsearch or graph databases. Deploy
coordinated search redaction, trusted Fence lookup and credential-preserving
clients before relying on metadata privacy. The earlier undeployed design's
`c47b632c18af` visibility migration has been removed; an installation that applied
that experimental revision needs migration-history reconciliation before switching.

Run `pytest tests/visibility` for both-backend privacy tests and
`pytest tests --ignore=tests/visibility` for legacy regressions. Use disposable
PostgreSQL databases only. The HTTP SDK fixture is
`python -m tests.visibility.local_server --port 58001`.
