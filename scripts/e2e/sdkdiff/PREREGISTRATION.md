# sdkdiff pre-registration

Registered 2026-11-07, committed BEFORE any scenario was executed against any driver.
Later changes go only in the "Amendments" section at the end, each with a reason and a timestamp.
Oracles are not tuned after seeing campaign output, except to remove a harness artifact (recorded as an amendment).

## 1. What is compared

The same scenario (a sequence of SDK-level operations) is run once per SDK, each against its own
fresh copy of one seeded throwaway keyorix-server (SQLite, synthetic data only), through a recording
reverse proxy. Because every SDK starts from an identical database snapshot, server state is identical
across SDKs for the whole scenario. A scenario never spans more than one server lifetime.

Clients under test (SDK repo `keyorix-sdks`, checked out at the commit recorded in each report):
Go (`go/`), Node (`node/`), Python (`python/`), Java (`java/`; reduced API: no projects/environments ops).
The standalone repos `keyorix-go/-java/-node/-python` are archive pointers and are NOT used.
Not covered in this first version: the generated Go client `cli/internal/apiclient`, the CLI, the MCP
server (reason: different operation vocabulary; listed as follow-up, not silently skipped).

Operations: `construct`, `health`, `login`, `list_secrets`, `get_secret`, `list_projects`,
`create_project`, `list_environments`. An op an SDK does not offer is "N/A" for that SDK and is excluded
from comparison; N/A is not a discrepancy but is reported in the coverage matrix.
An argument that a language cannot express (e.g. a negative id for Go `uint`) yields outcome `inexpressible`
for that SDK; excluded from comparison for that step, reported as a type-domain note.

## 2. Normalisation (what "equal" means)

Wire request, per request the proxy sees (the proxy sees requests exactly as the SDK sent them):
- method (exact)
- path: percent-decoded once; trailing slash and duplicate slashes are significant
- query: percent-decoded as Go `url.ParseQuery` does (`+` is space); compared as sorted multiset of key/value
- Authorization: exact
- Content-Type: media type only (parameters such as charset are informational)
- body: parsed with number preservation, re-serialised with sorted keys; non-JSON bodies compared as exact bytes
- body presence on GET/HEAD
- the number of requests per step

Informational only (counted, never a discrepancy): raw percent-encoding style (`+` vs `%20`, hex case,
`~`, `*`, `!'()` and `/` left raw or encoded), Content-Type parameters, User-Agent, Accept, Accept-Encoding,
Host, Connection, Content-Length (when body is equal), JSON key order, whitespace in bodies,
time string representation when the parsed instants are equal.

Decoded result as seen by the caller, as emitted by each driver in a fixed JSON shape:
secrets `{id,name,type,project_id,environment,created_at}`, projects `{id,name,description,created_at}`,
environments `{id,project_id,name}`, strings and booleans verbatim. Absent/null/""/0/zero-time are NOT merged:
`null` vs `""` is a result difference (category R1, low severity "empty-vs-null").
Server-generated volatile values (timestamps and ids of rows created during the scenario, session tokens)
are compared by type/format only; seeded rows are compared exactly. `login` returns only `{token_len>0}`.

Error classes (driver maps the SDK's native exception/value to one of):
`auth` (SDK's authentication error type), `not_found` (SDK's secret-not-found type), `http` (generic HTTP-status
error, status exposed when the SDK exposes it), `network`, `timeout`, `decode`, `validation` (client-side rejection),
`other`. The driver maps by the native type, not by guessing from the status, so the SDK's own mapping is what is tested.
Expected canonical mapping for a well-formed scenario: server 401 -> `auth`; client-side match miss in get_secret
-> `not_found`; every other non-2xx -> `http` with that status; connection failure -> `network`; exceeding the
caller-set timeout -> `timeout`; 2xx with undecodable body -> `decode`.

## 3. Oracles and categories

Pairwise/partition oracles (SDKs are partitioned by normalised signature; more than one block = discrepancy):
- W1 method/path differs; W2 query multiset differs; W3 Authorization differs; W4 body differs;
  W5 Content-Type media type differs; W6 request count differs (retry/redirect behaviour)
- R1 decoded result differs; R2 one SDK succeeds and another errors
- E1 error class differs; E2 exposed status differs
- V1 `construct` accepted by some SDKs and rejected by others
Absolute oracles (hold for each SDK separately; common-mode failures are invisible to pairwise oracles):
- E3 redaction: an error's string form must not contain the server response body or the bearer token
  (canary strings are injected in fault bodies and are used as tokens)
- S1 spec conformance: every recorded request must use only methods/paths/query parameters declared for that
  operation in `server/http/handlers/openapi.yaml`; S2: an SDK-formed request for a valid scenario must not be
  rejected with 400/404/422 by the server
- T1 timeout: with a caller-set timeout T and a server delay of at least 3T, the call must fail within 3T + 1s
- H1 harness health: proxy rejection, driver crash, driver protocol error, server restart failure are counted
  separately as harness artifacts and never as findings.

## 4. Fault injection (proxy, per step, optional)

`status{code,body}`, `close` (connection dropped), `redirect{code,location}`, `empty200`, `badjson200`,
`html200`, `wrongtype200`, `null_data200`, `nodata200`, `slow{ms}` (delay then pass through), `bigbody{bytes}`.
Applies to the first `times` requests of that step; synthetic faults do not contact the server.

## 5. Scenario generation

Phase A (deterministic edge matrix): every op crossed with an edge-value list per argument (Unicode NFC/NFD pairs,
combining marks, ZWJ, RTL, NUL/control chars, CRLF, long values 1 KiB/64 KiB/1 MiB, empty/null/absent, space,
`+ % & = # ? / \ ; : @ " ' < > ~ * ! ( )`, percent-encoded lookalikes `%2F %00 %25`, dot segments,
2^31/2^32/2^53/2^63/2^64 and negative integers), base URL variants, token variants, timeouts and the faults of section 4.
Phase B (random): seeded generator, same pools, sequences of 1-6 steps, with references to earlier results.
Phase B seeds are fixed in advance: 1..N, N chosen by budget. Value added by fuzzing = number of distinct
discrepancy signatures found in phase B that were NOT found in phase A. If that number is 0 the report says
"fuzzing added nothing over the deterministic matrix".

## 6. Validation of the harness (must pass before any real result is reported)

Planted defects, injected in the driver layer only when `SDKDIFF_PLANT=<id>` is set (default off):
- P1 python: environment value percent-encoded one extra time before the SDK encodes it (double encoding)
- P2 node: query parameter `include_value=true` dropped on the secret-value request
- P3 go: driver maps HTTP 404 into class `auth`
- P4 python: trailing slash appended to the request path
- P5 node: Authorization scheme sent as `bearer` (lower case)
- P6 java: environment value converted to NFD before the SDK sees it
- P7 python: empty description sent as `null` instead of `""` in create_project
Detection criterion: with a plant active, the validation set V (phase A scenarios tagged `validation`, plus phase B
seeds 1..50) must produce at least one discrepancy whose category matches the plant (P1 W2, P2 W2, P3 E1, P4 W1,
P5 W3, P6 W2, P7 W4) and whose odd-one-out block contains the planted SDK.
Controls (must be silent): C1 self-pairs - each SDK driver run twice as two independent instances over V gives zero
discrepancies; C2 golden set - fixed hand-written scenarios on which SDK behaviour is expected to be identical
(list_projects, health ok, list_environments on a seeded project, list_secrets without filter on a seeded project,
get_secret of an existing short name) give zero discrepancies; C3 benign re-encoding - encoding-style differences
between SDKs appear only under informational counters, never as discrepancies.
If a plant is missed or a control is noisy, the harness is fixed and validation is re-run; every such fix is an amendment.

## 7. Finding handling

Each discrepancy is minimised (delta debugging over steps, then over string contents, preserving the same
signature) and replayed at least 3 times from a fresh snapshot with an identical signature; otherwise it is classified
"harness artifact (non-deterministic)". Classes: SDK bug / spec ambiguity / server bug / harness artifact.
Security-relevant findings (secrets/tokens leaked to logs or other hosts, credentials sent in cleartext or to an
unintended host, accepting a non-loopback http URL, header injection, auth bypass) go only to
`~/proj/sdkdiff-private/FINDINGS.md` and are flagged to the founder; not in PRs, commits or the public repo.
Everything else may be written up in public draft PRs. No merge, no push to main.

## 8. Budget and environment

pve01: only cores 0-1 until /root/wave4/done exists (expected 2026-11-08 02:00 UTC), then at most 4 cores,
nice 19, never CT 100/221/240/270, everything cleaned by 2026-11-09 22:00 UTC. Java is not installed on pve01,
so Java runs on the Mac with a small share of the load. Server and SDK commits are recorded in each run header.

## Amendments
(none yet)
