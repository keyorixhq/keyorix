### Fixed
- **Audit page, dashboard and compliance views no longer show raw event names.** About 145 server audit events that read as a snake_case name (anomaly, break-glass review, MFA reset, SCIM, dynamic-secret, key rotation, access review, legal hold and more) now have plain-words labels, including `auth.sso_login_session_failed`. Guarded by `web/src/utils/__tests__/eventLabelsParity.test.ts`, which reads the Go sources as text and fails when an emitted event has neither a label nor a reasoned entry in `web/scripts/audit-intentionally-unlabelled.mjs`.

### Testing
- **Real-backend spec for the dynamic-secrets refused-admin-DSN banner** (`web/e2e/real/dynamic-secrets-refused-dsn.spec.ts`). It skips until the web e2e harness seeds a config with a refused admin DSN.
