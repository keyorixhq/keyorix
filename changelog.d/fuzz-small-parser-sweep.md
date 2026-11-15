### Added
- **Fuzz coverage for eight previously-unfuzzed small parsers/formatters (I7 sweep).** New
  `go test` fuzz targets with real oracles, each red/green-proved against a planted defect:
  the audit checkpoint high-water codec (`auditverify` `FuzzHighWaterRoundTrip`,
  `FuzzParseHighWater`), the `audit_seals` parser (`FuzzParseSeals`), the retention-anchor
  codec (`FuzzRetentionAnchorParse`), the audit-list keyset cursor codec read from the
  `cursor=` request parameter (`core` `FuzzDecodeAuditCursor`, `FuzzAuditCursorRoundTrip`),
  the key-set manifest codec (`keyfiles` `FuzzManifestRoundTrip`), and the on-disk restore
  journal parser (`restorejournal` `FuzzJournalRead`). Each is registered in
  `scripts/fuzzing/targets.d/` and documents in its harness what it does not verify. No
  production code changed.
