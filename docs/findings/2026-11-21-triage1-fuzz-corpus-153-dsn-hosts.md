# FINDING: FuzzDSNHostsCoverDriverHosts — double-bracket host form `[[…]]` escapes ParseDSNHosts normalisation

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #153
**Harness:** `internal/dynamic/dsn_driver_differential_fuzz_test.go` / `FuzzDSNHostsCoverDriverHosts`
**Component:** `internal/core/dsn/dsn.go` — `ParseDSNHosts`, `SplitDSNHostList`
**Status:** **FIXED — correction 2026-11-22, see "Correction" below. Fix on branch
`fuzz/followup1-153-171-confirm` (commit `a00c38c0`), NOT YET MERGED (no PR opened pending
the security-sensitive-code review and Andrei's word).**
**Classification: DEFECT (validation fail-open, no live SSRF path for the forms checked)** —
this file's own 2026-11-21 "Variant sweep" and "Optional hardening" sections below concluded
ARTIFACT/no-action from an incomplete premise. Correcting here rather than rewriting history
below; see "Correction" immediately after this header block for what was wrong and what's
actually true.
**Severity: Low** (was stated as None; see "Correction").

---

## Correction (2026-11-22, FOLLOWUP1 session)

The "Variant sweep" and "Optional hardening" sections below reached the right answer about
**dialability** (no double-bracket form is dialable by the real driver — that part holds up
and is reconfirmed by FOLLOWUP1) but drew the wrong conclusion from it. They treated
`net.LookupHost(host)` returning an error inside `validateAdminDSNSingleHost`
(`internal/core/dynamic_secrets.go`) as "rejected at API time" / "DNS lookup ... errors, so
registration fails." It does not: that function's actual behaviour on a `LookupHost` error is

```go
addrs, err := net.LookupHost(host)
if err != nil {
    return nil // unresolvable at register time — actual connection fails at issue time
}
```

— an unresolvable host is **not an error**, it's treated as "can't check yet, allow it, the
real connection will fail later if it's bad." For `host=[[::1]]`, after `SplitDSNHostList`'s
single-strip it becomes `"[::1]"`; `net.ParseIP("[::1]")` returns `nil` (ParseIP doesn't accept
brackets); `net.LookupHost("[::1]")` errors (not a valid hostname) → `validateAdminDSNSingleHost`
returns `nil` → **the admin DSN registration succeeds**, without ever having correctly
classified `::1` as the loopback address it actually is.

So "the validator skips the check" (said below) was true but understated: skipping the check
here means *accepting the registration*, not rejecting it. The reason this was still not a live
SSRF — and the reason severity is Low, not the Medium/High an accepted-but-unvalidated loopback/
link-local/IMDS admin DSN would otherwise warrant — is exactly what the sweep below already
proved: the *driver* independently can't dial this same malformed string either
(`net.JoinHostPort`/`SplitHostPort` both fail on it before any network access). The bug is real
(the validator and the driver disagree about what `[[::1]]` names, and the validator's
disagreement is a fail-open, not a fail-closed, outcome) but it is not currently exploitable
*for this exact string shape*, because the one thing that would make it dangerous — the driver
successfully dialing what the validator waved through — doesn't happen either. A future change
to bracket-handling in either the validator or the driver (or a future pgconn/pgx version) could
desynchronise them differently and make this exploitable; "no live bypass today" was correct,
"so no fix is needed" was not — see "Optional hardening" below, which called the fix cosmetic.
It isn't: it closes a validator fail-open, not just an oracle-hygiene complaint.

**Fix** (FOLLOWUP1, 2026-11-21, branch `fuzz/followup1-153-171-confirm`, commit `a00c38c0`):
`SplitDSNHostList`'s single `if`-strip changed to a `for`-loop, so `[[::1]]` reaches
`validateAdminDSNSingleHost` as the fully-stripped `::1`; `net.ParseIP("::1")` now succeeds;
`isPrivateIP` correctly blocks it. `FuzzDSNHostsCoverDriverHosts`'s own `stripBrackets` oracle
helper updated to match (also a loop), so the oracle and the real pgconn/driver behaviour agree
again. Red/green: `TestAdminDSNHost_DoubleBracketIPv6_Blocked` (red at `origin/main`, green at
this commit). Security closure fragment added: `dsn-double-bracket-ipv6-001`. Three new
corpus seeds pin the loopback, link-local, and multi-host double-bracket variants.

**Not yet landed**: this fix sits on an unpushed-then-pushed branch (now at
`origin/fuzz/followup1-153-171-confirm`), no PR opened. This touches the SSRF guard for admin
DSN registration — squarely a secretenv-adjacent security-sensitive change per CLAUDE.md's
testing/approval rules (Opus review required before merge, same category as KFZ-2026-157's
`internal/k8ssync` fix, which *did* get merged once without that review — see that finding for
what went wrong there). Do not repeat that: get the review before opening the PR, not after.

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
3. `validateAdminDSNHost` (`internal/core/dynamic_secrets.go`) calls `net.LookupHost` on the
   parsed host before persisting a DSN. **Correction (2026-11-22): `net.LookupHost("[]")`
   returning an error does NOT reject the registration** — `validateAdminDSNSingleHost` treats
   an unresolvable host as "skip the check, allow it" (`return nil` on the `LookupHost` error
   path), not as a rejection. See "Correction" above. The registration for `host=[[]]` itself
   still succeeds, same as the `[[::1]]` case below; it just also isn't dialable afterward,
   which is why this specific shape was never exploitable, for a different reason than
   originally stated here.
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

## Optional hardening (SUPERSEDED — this section was wrong, see "Correction" above)

*Original 2026-11-21 text, kept for the record rather than deleted:* "`SplitDSNHostList`'s
bracket-strip could still be made a loop instead of a single `if`, purely for oracle hygiene —
it would stop `FuzzDSNHostsCoverDriverHosts` from flagging this shape as a differential at
all, even though the differential has no security consequence. Not landed here: no live bypass
means no proving test obligation, and a change to this function for cosmetic-only reasons is
exactly the kind of unforced production edit CLAUDE.md's engineering practices caution against."

This was wrong on the premise, not just the conclusion: the differential is not cosmetic-only
(see "Correction") — it's a validator fail-open on malformed double-bracket hosts, independently
not exploitable today only because the driver also can't dial the same strings. FOLLOWUP1 landed
the loop-fix for the right reason (closing the fail-open) rather than the one speculated here
(quieting the oracle).

---

## Action required

**Get the PR opened and merged**, with the Opus security review CLAUDE.md requires for this
category happening *before* that PR merges, not retroactively:
1. Branch `fuzz/followup1-153-171-confirm` (commit `a00c38c0`) is pushed to `origin` but has no
   PR yet.
2. Open the PR, request the security-sensitive-code review (this is an SSRF-guard change,
   same category as auth/SSO/role-scope/secretenv/storage per CLAUDE.md's testing/approval
   rules), and do not merge until that review is recorded — unlike KFZ-2026-157/#4568, which
   merged without it and had to be reviewed after the fact.
3. Once merged, cite the merge-queue run's go1.27 test evidence for
   `TestAdminDSNHost_DoubleBracketIPv6_Blocked` (same pattern as KFZ-2026-157: the PR's own
   FAST-profile check reports `test-suite` skipped by design — the real evidence is in the
   `merge_group` run).
4. Update the corpus issue (keyorixhq/fuzz-corpus#153 — note: this issue was already closed
   2026-11-21 on the strength of this file's *original*, now-corrected, ARTIFACT/no-action
   conclusion; it needs a correcting comment, not just a registry update, and arguably
   shouldn't have been closed as ARTIFACT in the first place) and the KFZ registry entry with
   the actual merge SHA once this lands.

(FOLLOWUP1 was launched before this file's original, wrong confirmation landed, and
independently re-derived the correct answer with a real `pgx` module build rather than
inheriting this file's mistake — that's the useful kind of redundancy.)
