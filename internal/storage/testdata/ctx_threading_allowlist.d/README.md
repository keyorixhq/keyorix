# INV-STORAGE-32 allowlist (ctx_threading_guard_test.go)

One file per reviewed violation, so two PRs never edit the same file. A file holds one row:

    key <TAB> owning issue <TAB> reason

The file name is the key with `:` replaced by `__`, plus `.tsv`; the loader rejects a name
that does not match its key. A row whose violation is gone fails
`TestCtxThreading_NoStaleAllowlistRows`: delete the file.

Keys: `store:<Method>:first-param` | `iface:<Interface>.<Method>:first-param` |
`store:<Method>:reaches-root-ctx:<function that mints the root context>`

Groups of the rows present:

1. Exported `*LocalStorage` methods that are NOT `storage.Storage` members and run no
   tenant-scoped statement: construction-time wiring, introspection and lifecycle. There is
   no caller request to carry a tenant.
2. Detached background jobs that own their lifetime (they start a goroutine under
   `newBackgroundJob` and never serve a caller).
3. Audit write path (OPT-AUDIT-RT-1 owns it): `leaveAuditConnIdle` rolls back a failed
   pipelined attempt under a fresh timeout (`auditPipelineCleanupTimeout`) on purpose, because
   the caller's ctx may already be cancelled. It runs only ROLLBACK/Close on a connection the
   caller already holds. Follow-up once OPT-AUDIT-RT-1 merges: derive it with
   `context.WithoutCancel(ctx)` (#2507 follow-up, not done here).
