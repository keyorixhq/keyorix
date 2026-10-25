### Changed
- **The anomaly Isolation Forest pass now lives in `internal/anomaly`.** `anomaly_ml.go` and `isolation_forest.go` (pure code: no `*KeyorixCore`, no import of `internal/core`) moved out of `internal/core` with their two tests; `internal/core` keeps aliases, so no caller changed. Detection behaviour is unchanged. First pure-leaf extraction under ADR-121.
