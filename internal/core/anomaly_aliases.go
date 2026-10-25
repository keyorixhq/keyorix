package core

import "github.com/keyorixhq/keyorix/internal/anomaly"

// The Isolation Forest pass (anomaly_ml.go, isolation_forest.go) lives in
// internal/anomaly, a pure leaf: no *KeyorixCore, no import of this package.
// These aliases keep the names anomaly.go, anomaly_config.go and the core tests use
// valid, so no staying file changes.
type MLConfig = anomaly.MLConfig

var (
	mlOutlierAlerts  = anomaly.MLOutlierAlerts
	displayOrUnknown = anomaly.DisplayOrUnknown
	randomSeed       = anomaly.RandomSeed
)
