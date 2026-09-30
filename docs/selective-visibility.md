# Selective file visibility

An optional `visibility` field controls discovery of an IndexD record. Existing
records and omitted fields on creation default to `public`; this refers to
metadata, not permission to download bytes. Set `visibility: restricted` and a
nonempty list of absolute `authz` resource paths to hide the record from callers
without **fence / read-storage on every resource**, matching Fence's ordinary
Arborist download check. ACL-only records cannot be restricted.

```json
{"form":"object","size":123,"hashes":{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"urls":["s3://example/private.dat"],"authz":["/programs/MMRF/projects/private"],"visibility":"restricted"}
```

Bearer authorization takes precedence over the same-origin `access_token`
cookie. Arborist validates tokens; IndexD does not trust decoded JWT claims.
Anonymous Arborist download grants also apply. Validated IndexD Basic service
credentials can read everything, as can the explicit `indexd/read` action on
`/services/indexd/admin`. Writer credentials are trusted server credentials and
must never be distributed to browser users. Configure the existing auth driver
with Arborist; absence of Arborist never grants restricted reads. An unavailable
or malformed authorization service returns 503; invalid/unauthorized users see
no restricted metadata. All metadata responses are private and non-cacheable.

Filtering occurs in SQL before pagination, URL projection, and aggregation for
both backends. Denied direct, alias, version, DOS and DRS lookups return the same
404 as missing records. Hidden local identifiers cannot fall through to legacy
aliases or federation. Bulk requests omit denied records. Bundle snapshots are
visible only when their current descendants are all visible; dangling references
hide a bundle. This trades additional database work for avoiding snapshot leaks.

New versions inherit visibility; omitting authz on a restricted new version also
inherits its resources. Blank versions inherit visibility too. Changing a
restricted record to empty authz is rejected. Updates remain subject to existing
IndexD write authorization. Denied private mutations return 404 before revision
or record-shape errors can reveal the GUID. Restricting or changing resources for restricted
version families additionally requires update permission on the new resources.

Migration `c47b632c18af` defaults both storage layouts to public and adds a sticky
privacy-history marker. Downgrade refuses while restricted records exist.
**Do not run an older IndexD binary against restricted records**, even if the old
binary tolerates the extra column: it will ignore the policy and publish them.
When restrictions have ever existed, ordinary statistics count visible active
records; a month/year bounds their creation dates through the end of that month.
These are not historical deletion snapshots. Administrators retain the existing
historical global totals. The durable marker prevents deleted private records
from making old global totals public again.

IndexD alone cannot secure separate metadata copies in Elasticsearch, the graph,
MDS, exports, or previously public snapshots. Coordinate the Guppy, analysis,
Fence, SDK and ingestion changes using the MMRF GitOps selective-visibility
runbook. Graph nodes must reside under appropriately restricted project resources;
broad metadata policies do not substitute for download grants. Existing public
federated copies cannot be recalled by changing the local record. Passport-only
identities still use Fence's existing verified download flow, but discovery needs
a local Arborist download grant on the caller's token.

## Verification

Use only disposable databases. `pytest tests/visibility` exercises both backends,
all-resource authorization, anonymous/cookie/bearer reads, denial, projections,
versions, bundles, statistics, aliases and federation. The suite creates and
removes its test schema. Existing `pytest tests --ignore=tests/visibility` covers
the public API regressions. The migration also needs the normal operator database
backup and staged upgrade process before any production use.
