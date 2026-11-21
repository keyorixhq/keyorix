### Testing
- Extended the `server/authzdiff` cross-layer authorization differential harness to a
  further transport-enforced operation — risk-exception **approval**
  (`POST /api/v1/risk-exceptions/{id}/approve`) — bound to its REST router permission
  gate (`system.write` at global scope) and checked against the independent reference
  model, with a dedicated pending-exception fixture whose creator is a non-probed user
  so the dual-control business rules never vary by probed principal. Includes the
  committed deterministic strict sweep (via `TestV8StrictSweep`) and a planted-defect
  red proof (`riskexception-approve-router-gate-removed`) that removes the router gate.
