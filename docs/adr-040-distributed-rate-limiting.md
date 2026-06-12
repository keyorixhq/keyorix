# ADR-040: Cluster-wide login rate limiting

**Status:** Accepted
**Date:** 2026-06-12

## Context

Login brute-force protection was an in-process, in-memory sliding window: a
`map[ip][]time.Time` in the HTTP auth handlers, capping failed attempts at 10 per
IP per 15 minutes. The HA work (ADR-039) flagged this as the one remaining
per-replica gap: with N stateless replicas behind a load balancer, the limit is
enforced *independently* on each replica, so an attacker spreading attempts across
replicas gets up to N× the budget. The recommended mitigation was a gateway/WAF,
but Keyorix should be secure-by-default on-prem without requiring one.

## Decision

Move the limiter into the database so the count is shared across replicas.

- **`login_attempts` table** (`id`, `ip`, `attempted_at`) with a composite
  `(ip, attempted_at)` index. A failed attempt inserts a row; the gate counts an
  IP's rows within the window across the whole cluster.
- **Core API** (`internal/core/rate_limit.go`): `RecordFailedLogin(ctx, ip)`,
  `IsLoginRateLimited(ctx, ip)` (count ≥ `LoginMaxAttempts=10` within
  `LoginWindow=15m`), and `PruneLoginAttempts(ctx)`. The HTTP handlers' old
  free-function limiter is replaced by thin `AuthHandler` methods that delegate
  here — every login surface (password, TOTP verify, WebAuthn second-factor, and
  passwordless) now shares one cluster-wide limit.
- **Fail-open.** A storage error in `IsLoginRateLimited` returns `false` (allow).
  Rate limiting is a *backstop* layered on the real password/passkey check, not the
  auth gate itself; a transient DB hiccup must not lock every user out. Recording
  is best-effort for the same reason.
- **Bounded growth.** An always-on, single-replica-gated (ADR-039) maintenance
  goroutine prunes rows past the window hourly, independent of the opt-in retention
  purge scheduler — the limiter table must stay bounded even when purge is off.

## Why the write volume is acceptable

A row is written only on a *failed* attempt, and the gate is checked *first*: once
an IP reaches the budget it is rejected **before** another row is recorded. So a
single attacking IP writes at most ~`LoginMaxAttempts` rows per window before being
throttled. A distributed attack writes proportionally to the number of distinct
IPs — that broad case is still best handled at the gateway (noted below), but the
common single-IP / small-botnet brute force is now bounded cluster-wide by Keyorix
itself.

## Consequences

- The limit now holds across replicas — the ADR-039 per-replica gap is closed for
  the single-IP/small-botnet case.
- Each login does one indexed `COUNT` (and a failed one, one `INSERT`). Login is
  far less frequent than secret reads, so the added DB work is negligible.
- SQLite (single instance) works identically — it is just a table.

## Deferred

A truly distributed (many-IP) brute force, and request-rate limiting in general,
are still best enforced at the load balancer / API gateway / WAF — this ADR
hardens the credential-stuffing case, it does not replace edge rate limiting.
Per-account (not just per-IP) lockout; exponential backoff; CAPTCHA challenge.

## Verification

Core tests over SQLite: an IP is allowed under the budget and blocked at it; a
different IP is unaffected; attempts age out of the window; an empty IP is never
limited; prune removes aged rows. `make build` + full suite + `go vet` green.
