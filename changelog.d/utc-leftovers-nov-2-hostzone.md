### Fixed
- **Secret version and machine-token timestamps are stored in UTC on a non-UTC host.** `secret_versions.created_at` was stamped with the host-zone clock, so on a server whose process zone is `+0900` SQLite stored it as `... +0900 JST`; it is now UTC. `MachineTokenExpiresAt` (HTTP and gRPC `IssueMachineToken`) now returns a UTC expiry, so the stored value and the `expires_at` in the response carry no host offset. Pinned by `TestHostZoneStamps_CoreWritesStoreUTC` (Asia/Tokyo, SQLite and PostgreSQL), `TestHostZoneStamps_SecretVersionCreatedAtAnyHostZone` and `TestMachineTokenExpiresAt_IsUTCWhateverTheClockZone`.

### Testing
- **The host-zone model-timestamp guard lost its one tracked defect row.** `TestEveryModelTimestampStampIsUTC` now lists only the harmless, test-pinned sites.
