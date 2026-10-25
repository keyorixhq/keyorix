package storage

// ProjectWithCounts is returned by ListProjectsWithCounts, adding aggregate
// counts so the frontend project list page can show secret/env totals.
type ProjectWithCounts struct {
	ID               uint   `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SecretCount      int64  `json:"secret_count"`
	EnvironmentCount int64  `json:"environment_count"`
	LastActivity     string `json:"last_activity,omitempty"` // most recent of project update or any secret change
	Deleted          bool   `json:"deleted"`                 // true when soft-deleted (only returned when includeDeleted)
	DeletedAt        string `json:"deleted_at,omitempty"`    // RFC3339 timestamp when soft-deleted
}
