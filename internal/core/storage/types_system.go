package storage

import (
	"time"
)

// ProjectUsageStat is one row in a usage report, aggregating all metrics for
// one project over the reporting window.
type ProjectUsageStat struct {
	ProjectID     uint   `json:"project_id"`
	ProjectName   string `json:"project_name"`
	SecretCount   int64  `json:"secret_count"`    // active leaf secrets (is_secret=true, not deleted)
	ReadsInWindow int64  `json:"reads_in_window"` // audit_events: event_type="secret.read", success=true, in window
	UniqueReaders int    `json:"unique_readers"`  // distinct user_id values in those audit events
}

// UsageReport is the full usage response.
type UsageReport struct {
	WindowDays  int                `json:"window_days"`
	GeneratedAt time.Time          `json:"generated_at"`
	Projects    []ProjectUsageStat `json:"projects"`
}

// BillingProjectStat is one project's usage breakdown for a billing period.
type BillingProjectStat struct {
	ProjectID       uint   `json:"project_id"`
	ProjectName     string `json:"project_name"`
	SecretCount     int64  `json:"secret_count"`     // active leaf secrets at report time
	SecretReads     int64  `json:"secret_reads"`     // secret.read events in window
	SecretWrites    int64  `json:"secret_writes"`    // secret.create + secret.update + secret.rotate in window
	SecretRotations int64  `json:"secret_rotations"` // secret.rotate events in window (subset of writes)
	UniqueUsers     int    `json:"unique_users"`     // distinct human user_ids
	MachineReads    int64  `json:"machine_reads"`    // secret.read where actor_type='machine'
}

// BillingTotals aggregates BillingProjectStat across all projects.
type BillingTotals struct {
	Projects        int   `json:"projects"`
	SecretCount     int64 `json:"secret_count"`
	SecretReads     int64 `json:"secret_reads"`
	SecretWrites    int64 `json:"secret_writes"`
	SecretRotations int64 `json:"secret_rotations"`
	UniqueUsers     int   `json:"unique_users"`
	MachineReads    int64 `json:"machine_reads"`
}

// BillingReport is the response from GetBillingReport.
type BillingReport struct {
	From        time.Time            `json:"from"`
	To          time.Time            `json:"to"`
	GeneratedAt time.Time            `json:"generated_at"`
	Projects    []BillingProjectStat `json:"projects"`
	Totals      BillingTotals        `json:"totals"`
}

// StorageStats provides statistics about the storage system
type StorageStats struct {
	TotalSecrets   int64      `json:"total_secrets"`
	TotalUsers     int64      `json:"total_users"`
	TotalRoles     int64      `json:"total_roles"`
	TotalSessions  int64      `json:"total_sessions"`
	TotalAuditLogs int64      `json:"total_audit_logs"`
	DatabaseSize   int64      `json:"database_size_bytes"`
	LastBackup     *time.Time `json:"last_backup"`
}
