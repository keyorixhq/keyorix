package storage

// migrateDatabase steps for anomaly_alerts.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"gorm.io/gorm"
)

// alterAnomalyAlerts is one of migrateDatabase's ordered steps (factory.go).
func alterAnomalyAlerts(db *gorm.DB, exec func(string) error) error {
	// Anomaly alerting: additive `alerted` flag (false = not yet pushed out).
	if tableExists(db, "anomaly_alerts") && !columnExists(db, "anomaly_alerts", "alerted") {
		if err := exec("ALTER TABLE anomaly_alerts ADD COLUMN alerted BOOLEAN DEFAULT FALSE"); err != nil {
			return err
		}
	}
	// Companion index (models.AnomalyAlert.Alerted is `gorm:"default:false;index"`); see
	// the secret_nodes.classification companion-index comment above for why this is
	// gated on the table only, not on the ALTER above having just run.
	if tableExists(db, "anomaly_alerts") {
		if err := exec("CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_alerted ON anomaly_alerts (alerted)"); err != nil {
			return err
		}
		// Companion composite index for CreateAnomalyAlert's dedup count (see
		// models.AnomalyAlert's doc comment). Every column already exists on any
		// anomaly_alerts table this code can meet (accessed_by/ip_address/detected_at
		// are in the table's original shape), so no column gate is needed. Purely
		// additive: an older binary ignores an extra index, so no schema-epoch bump.
		if err := exec("CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_dedup ON anomaly_alerts (secret_node_id, alert_type, accessed_by, ip_address, detected_at)"); err != nil {
			return err
		}
	}
	return nil
}
