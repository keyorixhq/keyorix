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

All amendments below were made after the first phase-A runs had been looked at; none changes what counts as a
finding in a way that removes one. Each is a harness or control correction, listed with its reason.

- A1 (2026-11-07 ~17:00 CET) shim mode. The first raw golden run showed that the server answers with
  lower-case snake_case keys (`id`, `name`, `created_at`) while Node, Python and Java read `ID`, `Name`, `CreatedAt`,
  so every list result is empty-valued in those SDKs and `get_secret` can never match a name; the server also rejects
  `?environment=` with 400 and returns only 20 secrets per page. That is a finding (reported), and it hides everything
  behind it. A second run mode `-shim` is added: the proxy records the SDK request unchanged, then adapts only the
  copy sent upstream (drops `environment`, adds `page_size=100`) and renames the response keys to the PascalCase the
  SDKs read. Both modes are run and reported separately; "raw" is the real behaviour, "shim" is the deeper comparison.
- A2 golden set (control C2) is evaluated in shim mode and no longer contains `list_projects` or an unfiltered
  `list_secrets`: the server's project objects have no `created_at`, so Go (zero time), Node (null) and Python
  (empty string) legitimately represent the missing field differently (reported as R1 low severity, not hidden), and
  the seeded secret list deliberately contains names that expose Java's missing JSON unescaping (reported). The golden
  scenarios are now: health, list_environments of the seeded project, create_project with a plain name, login, two
  `construct` with accepted URLs.
- A3 oracle/driver corrections: (a) request #j is compared only among SDKs that made a request #j, a differing count
  is reported once as W6 (before, one root cause produced five signatures); (b) S1 is evaluated on the first request of
  a step with an ordinary base URL only (redirect-followed requests and deliberately malformed base URLs made noise);
  (c) E1 signatures bucket the server status (401 / other 4xx / 5xx / none) instead of using the exact status;
  (d) E3 also matches the escaped (`repr`/quoted) form of the token, because Python and Java print the header value
  escaped; (e) the Python driver mapped every `ValueError` to `decode`, now only `JSONDecodeError`/`UnicodeDecodeError`.
- A4 the standalone SDK driver for Go cannot be built on pve01 (Go 1.24, SDK needs 1.26): drivers and the
  orchestrator are cross-compiled on the Mac and shipped as binaries; Java is not available on pve01 (no JDK) and runs
  on the Mac only.

## Amendment A5 (sink family and oracle X1)

Added before any sink scenario was run against a campaign. A /sink path on the recording proxy records requests and answers 200. A redirect fault target @sink expands to the proxy sink URL on a different origin (localhost vs 127.0.0.1). Phase S generates 7 ops x redirect codes 301/302/303/307/308. Oracle X1: any recorded request whose Host starts with localhost: and carries an Authorization header is a finding (credential forwarded to another origin). Expected for controls: no SDK forwards. Results of X1 are security-relevant and are recorded only in private notes.

## Amendment A6 (late-recorded requests)

Found while minimising W6|health (did not reproduce alone): the proxy recorded a request only when its handler finished, so a request the SDK had already abandoned (timeout, 8 MB bigbody, slow fault) was attributed to the NEXT scenario, inflating request counts (W6), and producing spurious ok-vs-err and response-shape signatures after fault scenarios. Fix: Drain waits (max 12 s) for in-flight handlers. This is a harness artefact, not an SDK finding. All results gathered before this fix are kept as out-preA6 and are not used for the final counts. The full A and B campaigns, controls and plants are re-run with the fixed binary. Rules otherwise unchanged.

## Amendment A7 (SDK source pinned to origin/main; shim retired)

Found before any result was reported: the keyorix-sdks checkout used so far (branch ci/skip-sonar-for-dependabot) was 129 commits behind origin/main. Findings against it, in particular all contract-drift signatures (PascalCase server keys, the environment query parameter, pagination), described already-fixed code and are discarded. From here every run uses a detached worktree of origin/main (e972b6e, Merge PR #75) as the SDK source. On it the golden set is silent in raw mode (0 signatures, 4 SDKs) and the A1 shim only adds noise, so the shim is retired: all final campaigns are raw. Pre-A7 outputs are kept in out-preA6 for the record and excluded from counts. Everything else (oracles, planted defects P1..P7, controls C1/C2, honesty metric) is unchanged and is re-run from scratch.

## Amendment A8 (secrets API of v0.3.0)

Found by reading raw outcomes of the first A-raw run on the pinned SDKs (not by a signature): getSecret/listSecrets with an environment name only were removed in v0.3.0, so every secrets scenario returned the same "removed" error on all SDKs and the secrets path was silently NOT covered (vacuous agreement; the run showed zero secrets signatures). Drivers were re-targeted: list_secrets(env) and get_secret(name, env) now call the project-scoped API with project fixed to "alpha"; new ops get_secret_in, get_secret_by_ref and list_deleted_secrets(project id) were added; the Java driver now also covers list_projects and list_environments. Generators gained the new ops (edge-ref family, ref/path edge cases, project id pool); the golden set gained list_secrets("production") and get_secret_in(alpha, production, db-password). The Node driver reports purge_at as "" when null (driver-level normalisation, not an SDK finding). Lesson recorded for the report: the first honest oracle for a campaign is "did the operation actually run", so the summary now also prints the share of scenarios that ended in the removed-API error.
