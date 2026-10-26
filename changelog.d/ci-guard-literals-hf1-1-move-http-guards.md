### Testing
- **Static ACL-gate guards moved to `server/httpguards`.** The three go/ast guards
  `secret_acl_gate_guard_test.go`, `grant_primitive_gate_table_test.go` and
  `share_secret_isgroup_guard_test.go` moved unchanged out of `server/http` into a
  test-only package. Their path literals (`internal/core/`, `internal/storage`, ...)
  made the merge queue's selector run all six `server/http` legs for any
  `internal/core` or `internal/storage` change; a core test-file edit now runs 7 legs
  instead of 13. Closure row `AUTHZ-GUARDS-3423` names the new package.
