# sdkdiff hostile-server mode: rules

Registered 2026-11-07, committed BEFORE the first hostile-mode run against any SDK driver.
Later changes go only in the "Amendments" section, each with a reason. Oracles are not tuned after seeing output
except to remove a harness artefact (recorded as an amendment).

This mode depends on the cross-SDK differential harness (draft PR #4035, branch `fuzz/sdk-differential`): it reuses its
drivers, driver protocol, `Driver` process management and the SDK-pinning rule (always test a fresh `origin/main`
checkout of `keyorix-sdks`). Synthetic data only; the mock server listens on loopback.

## 1. Question

The client's trust boundary is the server response. For every SDK operation, the mock server returns the valid response
sequence the real `keyorix-server` produces (shapes captured once from a throwaway server, see `templates.go`), and
mutates exactly one response. What does each of Go / Node / Python / Java do with it?

## 2. Operations, targets, scenarios

Request classes: H health, A login, P projects list, C project create, E environments list, L secrets list (paged),
V secret value (`/secrets/{id}?include_value=true` and `/secrets/value?ref=`), D deleted-secrets list.
A scenario is (operation, target class); the mutation is applied to the first request of the target class (or to all
requests of that class when the mutation says `times=all`); every other response in the call is the valid template.

| id  | operation                                   | valid request sequence | target |
|-----|---------------------------------------------|------------------------|--------|
| S01 | health                                      | H                      | H      |
| S02 | login                                       | A                      | A      |
| S03 | list_projects                               | P                      | P      |
| S04 | create_project (Java: N/A)                  | C                      | C      |
| S05 | list_environments(2)                        | E                      | E      |
| S06 | list_secrets(production)                    | P E L                  | L      |
| S07 | get_secret(db-password, production)         | P E L V                | V      |
| S08 | get_secret_by_ref(alpha/production/db-password) | V                  | V      |
| S09 | get_secret_in(alpha, production, db-password)   | V                  | V      |
| S10 | list_deleted_secrets(2)                     | D                      | D      |
| S11 | list_secrets(production)                    | P E L                  | P      |
| S12 | list_secrets(production)                    | P E L                  | E      |
| S13 | get_secret(db-password, production)         | P E L V                | L      |

A mutation lists the scenarios it applies to. Framing, status, header and timing mutations run on the representative
set S01, S02, S03, S06, S07, S08, S10; content mutations run on every scenario whose target class carries the mutated
field.

## 3. Mutation catalogue (identifiers are fixed here; parameters in `mutations.go` must match)

Expectation codes: R reject (a success result is an O3 violation); A accept (benign; success with the unchanged
result expected, an error is reported as "unexpected rejection", used by the controls); X exact-or-error (success
must carry exactly the injected value or id, an error is fine; a different value is an O3/O6 violation);
E either (no verdict from the mutation, only O1, O2, O4 and the O5 comparison apply).
A suffix `(low)` marks R cases that are syntax or framing strictness rather than content (reported separately).

Nesting, in an extra unknown field of the top-level object unless stated:
N01 array depth 100 E, N02 array 10 000 E, N03 array 1 000 000 E, N04 object 100 E, N05 object 10 000 E,
N06 object 1 000 000 E, N07 `data` replaced by a 10 000-deep array R, N08 same with 1 000 000 R,
N09 `value`/`token` replaced by a 10 000-deep array R (A, V), N10 alternating array/object 10 000 E.

Bulk and framing:
B01 string of 1 GiB inside the main string field, EOF-framed (no Content-Length), streamed E;
B02 same field of 100 MiB with an honest Content-Length E;
B03 Content-Length 100 MiB, valid short body, connection closed R(low);
B04 Content-Length 10 less than the body R; B05 Content-Length 1000 more than the body, then close R;
B06 no Content-Length, complete body, close A; B07 no Content-Length, body cut at 60 %, close R;
B08 two different Content-Length headers R(low); B09a `Content-Length: -1` R(low), B09b `Content-Length: abc` R(low);
B10 Transfer-Encoding chunked plus Content-Length E; B11 status 500 with a 100 MiB error body, EOF-framed E.

Timing (the call is made with a 5 000 ms caller timeout): T01 body dripped at 1 byte per 250 ms E, T02 headers sent,
then silence E, T03 half of the body, then silence E, T04 connection accepted, no response at all E,
T05 headers dripped at 1 byte per 100 ms E.

Reset and truncation: R01 TCP reset after 50 % of a declared-length body R, R02 clean close after 50 % R,
R03 reset right after the request R, R04 close in the middle of the status line R,
R05a/b/c/d EOF-framed body cut after 1 byte / 10 bytes / len-2 / len-1 R,
R06 chunked, no terminating chunk, close R, R07 valid chunked A, R08 valid chunk extensions A,
R09 valid trailers A, R10 one-byte chunks A, R11 non-hex chunk size R, R12 chunk size 0xFFFFFFFFFFFFFFFFFF R,
R13 chunk size larger than the data, then close R, R14 early zero chunk followed by more data R,
R15 bare LF chunk lines E, R16 1 MiB chunk extension E.

Text, in the main string field (value/token/name) unless stated:
U01 raw byte 0xFF R, U02 0xC3 0x28 R, U03 overlong C0 AF R, U04 encoded surrogate ED A0 80 R, U05 UTF-8 BOM before the
document E, U06 lone high surrogate escape E, U07 lone low surrogate escape E, U08 reversed surrogate pair E,
U09 escaped NUL X, U10 raw NUL R(low), U11 raw CR LF R(low), U12 escaped CR LF X, U13 escapes `\/ \b \f \t é` X,
U14 escaped surrogate pair X, U15 value ending in a backslash X, U16 (V) `name` containing escaped quotes and the
text `value`, X for the real value, U17 (V) a nested decoy `"value"` key inside `secret` before `data.value` X,
U18 1 MiB string X, U19 16 MiB string X, U20 64 MiB string E, U21 1 MiB key name E, U22 UTF-16LE body with BOM R.

Shape and duplicates: D01 duplicate key (real first, other second) E, D02 duplicate key (other first) E,
D03 duplicate `data` E, D04 `data` missing R, D05 `data` null R, D06 `data` [] R, D07 `data` a string R,
D08 value number R, D09 value null R, D10 value object R, D11 value array R, D12 value key missing R,
D13 list is an object R, D14 list items null/number/string R, D15 list item without name E, D16 trailing garbage R(low),
D17 two concatenated documents R(low), D18 empty body R, D19 whitespace-only body R, D20 `null` R, D21 `[]` R,
D22 `"str"` R, D23 `123` R, D24 `{}` R, D25 status 200 with an error envelope R, D26 `{"success":false,...}` R,
D27 comments in JSON R(low), D28 trailing comma R(low), D29 single-quoted strings R(low), D30 unquoted keys R(low).

Status: S01m 500 with the success body R, S02m 404 with it R, S03m 401 with it R, S04m 403 with it R,
S05m 302 without Location, success body R, S06m 204 with empty body R, S07m 201 where the SDK expects 200 E,
S08m status 999 R, S09m status line without reason phrase A, S10m malformed status line `HTTP/1.1 2000 OK` R,
S11m no status line (body only) R, S12m `100 Continue` interim, then the valid response A, S13m 500 whose body echoes the
request's Authorization header E, S14m 503 with `Retry-After: 99999999` E, S15m `HTTP/1.0 200` A.

Headers and encodings: H01 Content-Type text/html E, H02 no Content-Type E, H03 charset=utf-16 label on a UTF-8 body E,
H04 multipart Content-Type E, H05 10 000 extra headers E, H06 one 1 MiB header line E, H07 header without colon E,
H08 header containing NUL E, H09 gzip-encoded valid body (R unless the SDK sent `Accept-Encoding: gzip`, then A),
H10 gzip bomb, 1 GiB of data (only if the SDK advertised gzip) E, H11 unknown Content-Encoding R,
H12 `Content-Encoding: gzip` with a non-gzip body R, H13 truncated gzip stream R, H14 `Content-Encoding: br` R.

Pagination and size: G01 endless pages (`total_pages` = page + 1 on every page) E, G02 `total_pages` 2147483647 E,
G03a..f `total_pages` 1e18 / -1 / 0 / "x" / null / 1.5 E, G04 list of 100 000 items E, G05 list of 1 000 000 items E,
G06 deleted list of 100 000 items E.

Numbers, in the id field of the first list item or of `data` (P, E, L, D, C): I01 9007199254740993 X, I02 9223372036854775807 X,
I03 9223372036854775808 X, I04 18446744073709551616 X, I05 `1e3` E, I06 `1.0` E, I07 `1.5` E, I08 `-0` E, I09 `-1` E,
I10 `1e999` X, I11 `NaN` R(low), I12 `Infinity` R(low), I13 `0x10` R(low), I14 `007` R(low), I15 `"2"` E, I16 `true` E,
I17 `null` E, I18 a 1000-digit integer X, I19 -9223372036854775809 X, I20 12345678901234567890 X.
For X the true value is the injected decimal text; the downstream request path (the id the SDK sends next) and the
returned id are both checked.

Controls (benign, expectation A, must be silent): C0 no mutation, C1 pretty-printed JSON, C2 object keys in reverse
order at every level, C3 extra unknown fields at top level and in `data`, C4 `Content-Type: application/json; charset=utf-8`;
plus B06, R07-R10, S09m, S12m, S15m, and H09 when advertised.

## 4. Oracles (per SDK unless stated)

Common settings: caller timeout 5 000 ms on every call (Go WithTimeout, Node `timeout`, Python `timeout`, Java Duration);
wall deadline 12 s (2T + 2 s); the harness kills a driver that has not answered after 25 s. Resident set size of the driver process is
sampled every 50 ms with `ps`; ceiling 1 GiB; Java runs with -Xmx512m and Node with --max-old-space-size=512 as protection.

- O1 no crash, no non-SDK error type. Go: no panic or process exit, and the error message carries the `keyorix:` prefix
  or a `keyorix` error type; Python: the exception is an instance of `keyorix.KeyorixError`; Node: instance of the
  SDK's `KeyorixError`, and no unhandled rejection, no uncaught exception, no process exit; Java: instance of
  `KeyorixException`, and no StackOverflowError, OutOfMemoryError, NullPointerException, ClassCastException,
  NumberFormatException or any other Throwable (an uncaught Throwable in a non-main thread counts). Driver death counts.
- O2 bounded time and memory: call returned within the wall deadline and peak RSS at or below the ceiling. An answer
  that arrives after the deadline, a kill after 25 s, or a kill by the RSS sampler is a violation.
- O3 fail-closed: for expectation R no success result; for X success only with exactly the injected value; for lists, a
  success with fewer entries than the valid template under a truncation mutation counts as success (violation).
  A success of a value-returning operation (login token, secret value) with an empty string counts as a success.
- O4 the token never appears in an error message, in the driver's full error rendering (stack/cause chain; Node
  `util.inspect`), or in captured stderr. Test token `CANARY-TOKEN-7f3a9c1d5e2b8a40`; escaped (JSON, repr, percent) forms
  also count. Reflection by S13m is reported as O4r (informational): the server already knows the token.
- O5 cross-SDK agreement: per (scenario, mutation) the outcome class is `ok` / `err:<harness class>`; disagreement is
  listed and classified by hand as SDK bug / spec ambiguity / harness artefact. Mutations with expectation E show up
  only here.
- O6 numbers: for X cases a returned or forwarded id that differs from the injected id without an error is a violation
  (Node doubles above 2^53, Java truncation, anything similar).

Severity classes, assigned before runs: HIGH = O3 violation on V/A (a wrong, partial or empty secret value or token returned
as success) or O4 token disclosure; MEDIUM = O3 on lists/ids (O6), O1 crash or leaked foreign exception, O2 memory blow-up;
LOW = R(low) strictness, O2 slow-drip semantics, O5 ambiguity. A hostile server is a configured, TLS-authenticated
server, so none of these is remotely exploitable by a third party: the realistic attackers are a compromised server,
a trusted-CA MITM, or loopback http in dev.

## 5. Planted defects and controls (SDK copies in a scratch directory; the repository's SDK sources are never modified)

Each plant is a patch applied by `plants/make-plants.sh` to a copy of the SDK tree.
PH1 go: returns the partial text when the secret-value body is cut (expected O3, mutations R05b/B07/R02, scenarios S07-S09);
PH2 python: treats a 500 as success and parses its body (O3, S01m, S02-S10);
PH3 node: recursion over the decoded response with no depth limit (O1, N02, N05, N03, N06);
PH4 java: includes the Authorization header value in the exception message (O4, S01m, any error);
PH5 python: ids parsed through float (O6, I01, I02, I20);
PH6 python: ignores the caller timeout (O2, T02, T03, T04).
Detection criterion: with plant PHn, the run on the plant's mutation subset has at least one violation of the registered
oracle for the planted SDK that the unpatched baseline run of that SDK does not have at the same (scenario, mutation).
PH0 is a no-op patch (comment only) on all four SDKs: its verdict set must equal the baseline's (control).
Controls C0-C4 and the A-expectation mutations must produce zero O1-O4/O6 violations and an unchanged result on every SDK;
an SDK that rejects a benign variant is reported as "unexpected rejection" (SDK strictness or harness bug, decided by hand).
A missed plant or a noisy control means the harness is fixed and the validation is re-run; each fix is an amendment.

## 6. Finding handling

Each candidate is reduced to one (scenario, mutation, SDK) triple, replayed at least 3 times with identical verdict, and
size-parameterised mutations (nesting, bulk, lists) are run on their ladder (the three registered sizes) to give the smallest
registered size at which the violation appears. Classes: SDK bug / spec ambiguity / harness artefact. Security-relevant results
(token disclosure, fail-open on malformed, truncated or mismatched responses, crashes or hangs caused by server data,
corruption of ids or secret values) are written only to `~/proj/sdk-hostile-private/FINDINGS.md`, not to this repository,
a PR, a commit message or an issue. A clear, small SDK bug gets a suggested patch under `~/proj/sdk-hostile-private/patches/`.
Nothing is opened against the SDK repository.

## 7. Environment

Mac only: GOMAXPROCS 2, `nice -n 10`, at most 2 SDK runners in parallel, bounded memory as above, no broad pkill. pve01 is not used.
SDK trees under test: `sdks-hostile-base` = keyorix-sdks origin/main 64c66a8; `sdks-hostile-harden` = PR #88 head d39dafc
merged with origin/main (88cdecf, local merge, not pushed). Both run through the same matrix.

## Amendments

All amendments below were made after the control run (C0-C4 over the four SDKs, 260 records, silent) and before any
mutation family was run.

- A1 Health reads the status line only (the Go SDK ignores the body; the drivers report `true`). Body-content expectations
  R/X on scenario S01 are therefore treated as E, except for the status family S, R03 (reset) and R04 (cut status line).
- A2 The login driver returns only the token length, so X on S02 cannot be checked and is treated as E there.
- A3 Implementation file names: `templates.go`, `mutations.go`, `hostile_srv.go`, `hostile_run.go` in `scripts/e2e/sdkdiff`.
- A4 The driver output gained `sdk_error`, `full` (rendered error chain) and `side_events`; Node reports unhandled
  rejections and uncaught exceptions instead of dying, Java records uncaught exceptions of other threads. Existing fields are unchanged.
