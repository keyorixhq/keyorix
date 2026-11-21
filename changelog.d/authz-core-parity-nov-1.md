### Security
- **Core decides the route gate itself on 19 operations that relied on the transport
  alone (defence in depth, #4161).** The cross-layer authorization differential had core
  allowing, and every transport refusing, about 4,500 cases over secret auto-rotate,
  rotate, rollback and copy, environment clone and copy-secrets, per-secret ACL grant and
  revoke, role update, delete and permission add, user create (with and without
  assignments), group restore, role assign and member add, global invitation, project
  restore and share revoke. Each of these core entry points now makes the same permission
  decision the REST route gate and the gRPC interceptor make, for human and machine actors
  alike, with a typed refusal; an access request from a suspended account is refused in
  core as it is at authentication. No client-visible change: every request a client could
  make was already refused at the transport. The differential's known-04 waiver is narrowed
  to the four owner-pass cases still open, so a dropped core check anywhere else now fails
  the strict sweep.
