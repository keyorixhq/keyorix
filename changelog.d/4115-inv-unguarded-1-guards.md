### Testing

- New AST guard `TestEveryDirectMachineGrantEntryTagsSelfGranter` (report-only on pull requests for now): every HTTP handler and gRPC method that reaches the role-grant ceiling must tag the context with `WithSelfMachineGranter` on the machine-actor branch.
- New guard `TestMigrateDatabase_ExistenceSnapshotPrecedesEveryTableCreation`: every `tableExists` call written directly in `migrateDatabase` (not those inside the migration steps) runs before any table-creating `AutoMigrate`.
- Invariant index recounted; stale gRPC "Ledger gap" note removed.

### Fixed

- `PUT /api/v1/users/{id}/roles` now lets a directly authenticated machine actor replace roles as itself when it holds the needed permissions; before, the grant ceiling refused every machine actor.
