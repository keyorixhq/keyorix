### Testing

- authzdiff: bound three more operations into the cross-layer authorization
  differential — risk-exception approve (`system.write@global` router gate),
  risk-exception delete (core-enforced creator-or-admin-tier, modelled as a
  global admin role) and break-glass revoke (`roles.assign@project` at both the
  REST router and the gRPC interceptor, also binding the previously-unbound
  `BreakGlassService.RevokeBreakGlass` RPC). Coverage of in-scope matrix
  operations rises to REST 96/212 and gRPC 36/47. Each binding is red/green
  validated by a planted-defect self-test.
