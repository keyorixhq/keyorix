# ADR-066: Network (IP/CIDR) allowlist for personal access tokens

## Status

Accepted. Extends the PAT least-privilege model (ADR-042: scopes + project/environment
confinement) with a network dimension.

## Context

A personal access token is a bearer credential: whoever holds the string can use it. ADR-042
narrows *what* a token can do (permission scopes, project/environment confinement), but not
*from where* it can be used. A token leaked from CI logs, a laptop, or a `.env` file is
fully usable from anywhere on the internet until it is noticed and revoked. Regulated buyers
(NIS2 Art. 21 access control, DORA, ENS `op.acc.*`) routinely require that machine
credentials be usable only from known networks.

## Decision

Add an optional **CIDR allowlist** to a personal access token. When set, a request
presenting the token is accepted only if its source IP falls within one of the listed CIDR
blocks; otherwise it is denied with `403`.

- **Storage.** `PersonalAccessToken.AllowedCIDRs` — a JSON `[]string` of CIDRs (a bare IP is
  normalised to a `/32`/`/128` host route). Empty = no restriction (the back-compat
  default). CIDRs are validated at creation; an invalid block is rejected.
- **Enforcement at the auth boundary, on every transport.** The allowlist rides on the
  resolved `PATRestriction`, and the source IP is checked against it **on every request** —
  including HTTP cache hits, since the same token may arrive from different IPs. Both
  transports enforce it: the HTTP authentication middleware (`RemoteAddr`) and the gRPC
  auth interceptor (the gRPC peer address) — so the restriction cannot be bypassed by
  switching from HTTP to gRPC. It **fails closed**: an undeterminable or unparseable source
  IP is denied.
- **The source IP is the TCP peer (`RemoteAddr`), never a client-supplied header**
  (`X-Forwarded-For` is attacker-controlled and would make the control trivially bypassable).
  A deployment behind a reverse proxy must therefore terminate so `RemoteAddr` is the real
  client (e.g. PROXY protocol) for per-client allowlists to apply — documented as an
  operational requirement.
- **Surface.** `keyorix pat create --allowed-cidr 10.0.0.0/8` (repeatable), the
  `allowed_cidrs` field on the create API and token list, and a `from=…` segment in the CLI
  token-scope summary.

## Alternatives considered

- **Trust `X-Forwarded-For`.** Rejected: a security control keyed on a spoofable header is
  no control. Trusting it requires explicit trusted-proxy configuration, which is a separate
  concern; `RemoteAddr` is the safe default.
- **Enforce inside `ValidatePATToken` (the DB lookup).** Rejected: the result is cached, and
  the network check must run per-request against the live source IP, so it belongs at the
  per-request middleware chokepoint, after the (possibly cached) identity is resolved.
- **A global network policy instead of per-token.** Useful but coarser; per-token matches the
  ADR-042 least-privilege model and lets one workload's CI token be pinned without
  constraining interactive admins.

## Consequences

- Additive and behaviour-neutral by default: a token with no allowlist behaves exactly as
  before. The column is added by AutoMigrate; existing rows decode to "no restriction".
- Fail-closed: a misconfigured allowlist (or a proxy that hides the client IP) locks the
  token out rather than failing open — the safe direction for a credential control.
- Composes with ADR-042: a token can be simultaneously permission-scoped, project/environment
  confined, and network-restricted.
- A natural follow-up is the same allowlist on machine-identity tokens (ADR-023), which
  reuses `IPInCIDRs` and the same enforcement seam.
