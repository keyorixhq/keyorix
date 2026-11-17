- **INV-GRPCSVC-mapper-takes-rpc-ctx** A gRPC error mapper takes the RPC's `ctx` and hands it to
  `coreErrorStatus` (and so to `errclass.OfMutation` / `core.IsAuthorizeTransient`); it never
  substitutes `context.Background()`. A request whose context was canceled or timed out while a core
  call ran is an outage the client should retry (`Unavailable`, the gates' fixed text), as REST
  answers 503; with `context.Background()` an error that does not itself wrap `context.Canceled`
  (a driver's "interrupted" text after the cancel) was not recognised and answered `Internal`
  (GRPC-MAPPER-TAILS-1). A typed storage read fault keeps its `storage_unavailable` ErrorInfo
  under a canceled ctx. `mapDynamicError` answers any error the classifier does not know
  `Unavailable` already (the target database is the dependency), so the ctx changes nothing there.
  Guard: `TestFamilyMappers_CanceledContextIsUnavailable` and
  `TestFamilyMappers_CanceledContextTypedReadFaultKeepsDetail` (table over every family mapper,
  `family_mappers_canceled_ctx_test.go`); the audit-outage mapping guard flags a mapper that takes
  `ctx` and passes `context.Background()` (`audit_unavailable_mapping_guard_test.go`).
