# Live-server replay: pre-registered success rules

Written and committed BEFORE the first run against a real server. The
numbers below are the bar; the report states honestly which were met.
(2026-11-06, branch `fuzz/live-replay`.)

## What is being tested

A real `keyorix-server` process (built from this tree, SQLite, fresh temp dir,
synthetic data only) is driven over HTTP. Actor A, a project admin of tenant
A, makes a legitimate session. Every request of that session, and every
operation in the OpenAPI document, is then replayed as: another tenant's
admin (B), a lower role in the same tenant (V, project_viewer), a user with
no grant (N), a machine token of tenant B, a lower-role machine token of
tenant A, no auth, a garbage token, a tampered token, a logged-out session,
a revoked PAT, a revoked machine token and an expired PAT; with object ids
swapped to the other tenant's, mutated (neighbour, 0, -1, overflow, traversal),
with pagination and filter mutation on lists, and with batch bodies that mix
the victim's ids into the attacker's batch.

## Oracles (deny-direction only)

1. STATUS: the model denies the actor and the server answers 2xx.
2. LEAK: another tenant's canary prefix appears in any response body, any
   status, and was not sent in the request.
3. EFFECT: an observer-visible fingerprint of the world changes after an
   unsafe request the model does not allow (covers "403 but executed").

The model (`model.go`) is a small table derived from `internal/core/authz.go`
and `auth_bootstrap.go` defaultRoles. It is Unknown whenever unsure; Unknown
requests are never status-judged. A refusal where the model says Allow is
reported as `model-allow-refused` (model or availability divergence), never as
a security finding.

## Success rules

R1. Baseline completeness. The run on an unmodified server attempts every
    `/api/v1/*` operation in `openapi.yaml`, sends at least 2,000 probes, and
    at least 25 of the legitimate actor's positive controls return 2xx. If
    not, the run is reported as incomplete and nothing else is claimed.

R2. Planted-defect self-test (must pass before any result is believed).
    Level 1: an in-process fake API (default `go test`): clean = 0
    candidates; each of 5 plants (cross-tenant read, lower-role write,
    missing auth, 403-but-executed delete, filter leak) is reported with the
    expected class and actor and no candidate lands on an unplanted op.
    Level 2: the real server built with `go build -overlay` plants
    (cross-tenant secret authorization, lower-role write, PAT-revocation
    skip) must each surface as a candidate on the planted behaviour, and the
    unplanted build must not report those candidates (asserted by
    `TestLiveReplay` for every plant). The revoked machine token has no plant;
    its refusal is exercised but its detection is not proven. A plant that is not
    found voids the run: the harness is then declared broken, not the server
    clean.

R3. Finding rule. A candidate is a FINDING only when (a) its key (class,
    variant, actor, method, target) recurs in 3 independent fresh-server runs,
    and (b) it is classified, with a written reason, as one of: real bug,
    expected behaviour, harness bug. Anything else is reported as
    "unconfirmed candidate". Exploit details of real bugs go to the private
    findings file only.

R4. Model divergence. Report counts of `model-allow-refused`, `inconclusive`
    (400/404/405/409/422/429) and `server-error` per variant. Coverage is
    reported, not gated: the share of operations with at least one
    conclusive (non-400/422) probe from a denied actor. Two numbers are logged
    and must not be confused: authz coverage (a signed-in actor A, B, V, N, MA
    or MB with a Deny verdict) and any-actor coverage (also counts anon,
    garbage and other credential rejections, which is always close to 100%).

R5. A null result (zero confirmed findings) is a valid outcome and is
    reported as such.

R6. Run integrity. A run is void, not clean, if before the first or after the
    last probe any fingerprint path of the effect oracle does not answer 2xx
    (the oracle is blind there, or a probe destroyed a fixture), if any request
    got no HTTP answer, or if the server process exited. Seeding that cannot
    create a fixture (group, ACL, invitation, share, PAT) fails the run.

## Safety

- Only a throwaway server started by the test, on a free loopback port, with
  `t.TempDir()` storage and synthetic data. No real secrets, no real hosts.
- CT 221 (`keyorix-dast`) was inspected read-only. Nothing was written to
  it; its scheduled ZAP/Nuclei scans and shared database make it unsuitable
  for state-changing replay.
- pve01 CT 100 (mutation job) is not touched.
