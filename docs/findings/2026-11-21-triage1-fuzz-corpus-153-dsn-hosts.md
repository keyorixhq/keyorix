# FINDING: FuzzDSNHostsCoverDriverHosts — double-bracket host form `[[…]]` escapes ParseDSNHosts normalisation

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #153
**Harness:** `internal/dynamic/dsn_driver_differential_fuzz_test.go` / `FuzzDSNHostsCoverDriverHosts`
**Component:** `internal/core/dsn/dsn.go` — `ParseDSNHosts`, `SplitDSNHostList`
**Status:** **CLOSED — variant sweep complete, no live bypass found.**
**Classification: ARTIFACT** — real oracle differential (ParseDSNHosts vs. pgconn's own
normalisation), but confirmed benign: no double-bracket form, with or without a valid literal
inside, is dialable by the real driver while validation skips it. See "Variant sweep" below.
**Severity: None** — see "Variant sweep" below for why.

---

## Summary

`ParseDSNHosts("host=[[]]")` returns `["[]"]`.
pgconn's own host parser stores the raw string `"[[]]"` in `cfg.Host`.
The harness's `covered` function (`stripBrackets` applied to both sides) produces
`"[]"` (from ParseDSNHosts) vs `""` (from `stripBrackets("[]")`), which are not equal.
`t.Fatalf` fires.

The seed corpus entry added in this session:
```
internal/dynamic/testdata/fuzz/FuzzDSNHostsCoverDriverHosts/f0520501354fcac9
```
Input: `string("host=[[]]")`

---

## Code trace

`ParseDSNHosts("host=[[]]")` → `ParseDSNHostsFromKeyValue`:

1. `keywordValuePairsStrict` → map `{"host": "[[]]"}`.
2. `SplitDSNHostList("[[]]")`:
   - `net.SplitHostPort("[[]]")` fails (not `[host]:port` form; first `]` at position 2 is followed by `]` not `:`).
   - Has prefix `[`, suffix `]`, len > 2 → strips outer brackets → `"[]"`.
   - Returns `["[]"]`.

pgconn (`github.com/jackc/pgconn`) stores `cfg.Host = "[[]]"` literally (pgconn's parser does no bracket-normalisation for this form).

Harness `covered` check:
- `want = stripBrackets("[[]]") = "[]"` (strips one pair of outer brackets)
- `g = stripBrackets("[]") = ""` (strips the second pair)
- `"" ≠ "[]"` → crash.

This confirms the differential: `ParseDSNHosts` sees `[[]]` as the IPv6-bracket notation wrapping the string `[]`, while the harness's oracle (and by extension pgconn) see it as two levels of brackets.

---

## Blast radius

**Specific input `host=[[]]` has no live SSRF path.**

1. `net.JoinHostPort("[[]]", "5432")` → `"[[]]:5432"`.
2. `net.SplitHostPort("[[]]:5432")`: starts with `[`, finds first `]` at position 2, next char is `]` not `:` → error. Go's net stack cannot dial `[[]]`.
3. `validateAdminDSNHost` (`internal/dynamic/`) calls `net.LookupHost` on the parsed host before persisting a DSN. `net.LookupHost("[]")` returns an error → DSN registration is rejected at API time.
4. Double-bracket wraps of real IPs (e.g. `[[169.254.169.254]]`) follow the same parse failure path; none are dialable.

**Resolved 2026-11-21 (post-triage, same day):** traced the remaining variant space by hand
against pgconn's actual source (`github.com/jackc/pgx/pgconn/config.go`, cloned directly from
GitHub for this check — `proxy.golang.org`/`go mod download` is not reachable from this
orchestration environment, GitHub itself is) and confirmed empirically with the Go standard
library. See "Variant sweep" below — closed, no bypass.

---

## Variant sweep (closes the "undone work" above)

The open question was whether a double-bracket wrap of a **valid** literal — e.g.
`host=[[::1]]` (has a `:` inside) or `host=[[169.254.169.254]]` (no `:` inside — the two cases
are distinguished because `net.JoinHostPort` branches on exactly this) — could reach
`validateAdminDSNHost` in a form it skips (`net.ParseIP` rejects brackets, so the once-stripped
residue `"[::1]"`/`"[169.254.169.254]"` falls through to `net.LookupHost`, which errors →
"unresolvable, skip validation") while the real driver could still dial it.

It cannot, for a reason specific to pgconn's own key/value parser: **pgconn does not
bracket-strip at all.** `pgconn/config.go`'s key/value path stores `settings["host"]` raw —
for `host=[[::1]]` that's the literal 10-character string `"[[::1]]"`, unstripped — directly
into `config.Host` (`config.go:579`, `hosts := strings.Split(settings["host"], ",")`), which
`NetworkAddress` (`config.go:252`) then feeds straight into `net.JoinHostPort(host, port)`.

Verified with the Go standard library directly (no pgx build needed for this part — these are
pure `net` package primitives, version-independent):

```
JoinHostPort("[[::1]]", "5432")             = "[[[::1]]]:5432"
JoinHostPort("[[169.254.169.254]]", "5432") = "[[169.254.169.254]]:5432"
```

Both fail `net.SplitHostPort` / `net.ResolveTCPAddr` / `net.Dial` with `missing port in
address` — a pure address-parsing failure, before any DNS lookup or TCP attempt. Reason: in the
IPv6 case, `JoinHostPort` sees a `:` in the already-bracketed host and adds a THIRD bracket
layer; in the IPv4 case, no extra layer is added, but `SplitHostPort` looks for the host's
*first* `]` and expects a `:` immediately after it — finds the *inner* closing bracket instead,
and errors the same way.

So for every double-bracket form checked — empty (`[[]]`, already covered), IPv4 literal
(`169.254.169.254`, the IMDS case the SSRF guard exists for), and IPv6 literal (`::1`) — the
validator skips the check AND the real driver independently fails to dial the same string, for
two different reasons that both land before any network access. No live SSRF path exists
through this vector. 169.254.169.254/IMDS is not reachable this way.

**Scope correction:** `host=` key/value DSN syntax is libpq/pgconn-specific. MySQL
(`go-sql-driver/mysql`) does not use it — its DSN format is `user:pass@tcp(host:port)/db`
(verified against the real driver source, `dsn.go`'s `ParseDSN`) — so this vector is
Postgres-only; "whether MySQL... accept `[[X]]` forms differently" (listed as unverified below
in the original triage) does not apply.

---

## What this finding does NOT verify

- Whether `RevokeTarget` (`internal/core/dsn/revoke_target.go`, which also calls
  `ParseDSNHosts`) is reachable with an already-persisted `[[X]]`-form DSN — moot now that no
  such DSN ever becomes dialable, but not separately traced.
- MongoDB's URI-form connstring parser's handling of bracket forms — this finding's sweep
  covered only the key/value `host=` syntax (Postgres), not the URI syntax mongo and
  Postgres/MySQL URL forms share; MongoDB was never in scope for the `[[X]]` variant (that
  syntax doesn't appear in mongo URIs).

---

## Optional hardening (not required, not landed)

`SplitDSNHostList`'s bracket-strip could still be made a loop instead of a single `if`, purely
for oracle hygiene — it would stop `FuzzDSNHostsCoverDriverHosts` from flagging this shape as a
differential at all, even though the differential has no security consequence. Not landed here:
no live bypass means no proving test obligation, and a change to this function for cosmetic-only
reasons is exactly the kind of unforced production edit CLAUDE.md's engineering practices caution
against. Leave as a LEFTOVER if Andrei wants the oracle quieted.

---

## Action required

None. Closed — see "Variant sweep" above. (FOLLOWUP1, launched before this confirmation landed,
is independently re-deriving the same conclusion with a real `pgx` module build and will add a
pinned regression seed; that's expected redundancy, not wasted work.)
