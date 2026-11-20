- **INV-AUTHZDIFF-v5ext-risk-breakglass-gates** The authorization gate of
`riskexception.approve`, `riskexception.delete` and `breakglass.revoke` is
bound into the differential and checked against the independent reference
model: `riskexception.approve` is a router-gate differential on
system.write@global (core_refusal:"none", core leg excluded); `riskexception.delete`
is a core-enforced creator-or-admin-tier gate the model expresses as
globalAdminRole (core_refusal:"typed", core leg included); `breakglass.revoke`
is a roles.assign@project gate enforced at BOTH the REST router and the gRPC
interceptor (core_refusal:"none", core leg excluded). Why: V5EXT
authorization-completeness extension over the risk-exception and break-glass
families V5/V8 deferred (server/authzdiff/ops_v5ext_test.go documents the gate
of each endpoint and why the sibling endpoints — access-review attest/decide/
revoke, break-glass review — are NOT bound: their core_refusal is "typed" yet
core does not re-check the router's scoped permission, so the core leg would
allow a principal the router denies, a disagreement no waiver absorbs).
Guard: TestV5extStrictSweep (always-on, server/authzdiff/sweep_v5ext_test.go)
plus the three plants riskexception-approve-router-gate-removed,
riskexception-delete-core-gate-removed and breakglass-revoke-rest-gate-removed
(server/authzdiff/plants_test.go, AUTHZDIFF_PLANTS=1; each red when its gate is
dropped — 59/2/239 unexplained cases at introduction — and green on a clean tree).
