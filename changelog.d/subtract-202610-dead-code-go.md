### Internal
- **Removed seven Go functions nothing called** (found by `deadcode -test ./...`): `core.DefaultSecretValuePolicy`, `storage.CheckSchemaEpoch`, `solewriter.ActiveTracker` and its write-only global, `besteffortguard.DistinctPairs`, `fuzzworld.World.Migrate`, `testhelper.IsolateCLIHome` (its callers went with the old CLI) and a test-only `String` method. No behaviour change.
