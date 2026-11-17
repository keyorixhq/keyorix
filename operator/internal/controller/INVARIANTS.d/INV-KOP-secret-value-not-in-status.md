- **INV-KOP-secret-value-not-in-status** A fetched Keyorix secret value is written only
  into the target Kubernetes Secret's data — never into the CR `.status` (conditions,
  messages, `syncedHash`), a Kubernetes Event, or a returned error string. `.status` is a
  subresource commonly readable by principals holding no RBAC on the underlying Secret, so
  `syncedHash` is an HMAC fingerprint (keyed per-process), never the raw value or an
  unkeyed hash. Why: `hashData`/#124, the `fail*`/`setReady` message construction
  (`keyorixsecret_controller.go`). Guard: `FuzzReconcileAuthzBoundary` oracle 3
  (`operator/internal/controller`) plants a canary as the fetched value and asserts it
  never appears in `.status`/Events/error.
