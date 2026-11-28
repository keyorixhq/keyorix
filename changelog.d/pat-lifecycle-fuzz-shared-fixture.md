### Testing

- `FuzzPATValidateLifecycle` builds its SQLite fixture once per process instead of once per input, about 17x more executions per second on the same hardware (155/s to 2,700/s at `-parallel 1`, 549/s to 9,650/s at `-parallel 4`). Each input still gets a fresh `LocalStorage` and `KeyorixCore` and an emptied `notifications` table, and the input fails if anything but notification rows changed. All seven defects recorded in the file header still fail the harness.
