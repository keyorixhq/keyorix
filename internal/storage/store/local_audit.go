// local_audit.go — Audit log and anomaly alert operations for LocalStorage.
//
// Covers: LogAuditEvent, CreateSecretAccessLog, ListSecretAccessLogs,
//
//	GetAuditLogs, GetRBACAuditLogs,
//	CreateAnomalyAlert, ListAnomalyAlerts, AcknowledgeAnomalyAlert.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_audit.go.
package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	return ls.db.WithContext(ctx).Create(event).Error
}

func (ls *LocalStorage) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	return ls.db.WithContext(ctx).Create(log).Error
}

func (ls *LocalStorage) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	var logs []models.SecretAccessLog
	result := ls.db.WithContext(ctx).
		Where("secret_node_id = ? AND access_time >= ?", secretID, since).
		Find(&logs)
	return logs, result.Error
}

// scanTime portably scans a SQL timestamp that some drivers return as time.Time
// (Postgres) and others as a string from an aggregate like MAX() (SQLite).
type scanTime struct{ t *time.Time }

// Value satisfies driver.Valuer so GORM treats scanTime as a scalar field
// (not a relation); the queries are read-only so it is never actually written.
func (s scanTime) Value() (driver.Value, error) {
	if s.t == nil {
		return nil, nil
	}
	return *s.t, nil
}

func (s *scanTime) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		t := v
		s.t = &t
		return nil
	case []byte:
		return s.parse(string(v))
	case string:
		return s.parse(v)
	default:
		return fmt.Errorf("scanTime: unsupported type %T", value)
	}
}

func (s *scanTime) parse(str string) error {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, str); err == nil {
			s.t = &t
			return nil
		}
	}
	return fmt.Errorf("scanTime: cannot parse %q", str)
}

// MostAccessedSecrets ranks secrets by read count in the window, joining
// secret_nodes for the name/environment. Reads are the usage signal, so only
// access logs with action="read" are counted.
func (ls *LocalStorage) MostAccessedSecrets(ctx context.Context, projectID *uint, since time.Time, limit int) ([]storage.SecretUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	q := ls.db.WithContext(ctx).
		Table("secret_access_logs AS l").
		Select("l.secret_node_id AS secret_id, s.name AS secret_name, s.environment_id AS environment_id, COUNT(*) AS read_count, MAX(l.access_time) AS last_read").
		Joins("JOIN secret_nodes s ON s.id = l.secret_node_id").
		Where("s.is_secret = ?", true).
		Where("l.action = ?", "read").
		Where("l.access_time >= ?", since).
		Group("l.secret_node_id, s.name, s.environment_id").
		Order("read_count DESC, last_read DESC").
		Limit(limit)
	if projectID != nil {
		q = q.Where("s.project_id = ?", *projectID)
	}

	type row struct {
		SecretID      uint
		SecretName    string
		EnvironmentID uint
		ReadCount     int64
		LastRead      scanTime
	}
	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}

	stats := make([]storage.SecretUsageStat, 0, len(rows))
	for _, r := range rows {
		stats = append(stats, storage.SecretUsageStat{
			SecretID: r.SecretID, SecretName: r.SecretName, EnvironmentID: r.EnvironmentID,
			ReadCount: r.ReadCount, LastRead: r.LastRead.t,
		})
	}
	return stats, nil
}

// UnusedSecrets returns secrets whose most recent read is older than
// notReadSince (or that have never been read), ordered never-read first. Only
// real secrets (is_secret) are considered, not folder nodes.
func (ls *LocalStorage) UnusedSecrets(ctx context.Context, projectID *uint, notReadSince time.Time) ([]storage.UnusedSecretStat, error) {
	q := ls.db.WithContext(ctx).
		Table("secret_nodes AS s").
		Select("s.id AS secret_id, s.name AS secret_name, s.environment_id AS environment_id, MAX(l.access_time) AS last_read").
		Joins("LEFT JOIN secret_access_logs l ON l.secret_node_id = s.id AND l.action = ?", "read").
		Where("s.is_secret = ?", true).
		Group("s.id, s.name, s.environment_id").
		Having("MAX(l.access_time) IS NULL OR MAX(l.access_time) < ?", notReadSince).
		Order("(MAX(l.access_time) IS NULL) DESC, last_read ASC")
	if projectID != nil {
		q = q.Where("s.project_id = ?", *projectID)
	}

	type row struct {
		SecretID      uint
		SecretName    string
		EnvironmentID uint
		LastRead      scanTime
	}
	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}

	stats := make([]storage.UnusedSecretStat, 0, len(rows))
	for _, r := range rows {
		stats = append(stats, storage.UnusedSecretStat{
			SecretID: r.SecretID, SecretName: r.SecretName, EnvironmentID: r.EnvironmentID,
			LastRead: r.LastRead.t,
		})
	}
	return stats, nil
}

// GetAuditLogs retrieves audit events with optional filtering and pagination.
func (ls *LocalStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.AuditEvent{})
	page, pageSize := 1, 20

	if filter != nil {
		if filter.ProjectID != nil {
			query = query.Where("project_id = ?", *filter.ProjectID)
		}
		if filter.UserID != nil {
			query = query.Where("user_id = ?", *filter.UserID)
		}
		if filter.Action != nil {
			query = query.Where("event_type = ?", *filter.Action)
		}
		if len(filter.Actions) > 0 {
			query = query.Where("event_type IN ?", filter.Actions)
		}
		if filter.StartTime != nil {
			query = query.Where("event_time >= ?", *filter.StartTime)
		}
		if filter.EndTime != nil {
			query = query.Where("event_time <= ?", *filter.EndTime)
		}
		if filter.Success != nil {
			query = query.Where("success = ?", *filter.Success)
		}
		if filter.ActorType != nil {
			query = query.Where("actor_type = ?", *filter.ActorType)
		}
		if filter.AfterID != nil {
			query = query.Where("id > ?", *filter.AfterID)
		}
		if filter.Page > 1 {
			page = filter.Page
		}
		if filter.PageSize > 0 {
			pageSize = filter.PageSize
		}
	}

	var total int64
	query.Count(&total)

	// Cursor mode (SIEM export): ascending by id, no page offset — the caller
	// advances by passing the last seen id as AfterID on the next request.
	if filter != nil && filter.Ascending {
		var events []*models.AuditEvent
		if err := query.Order("id ASC").Limit(pageSize).Find(&events).Error; err != nil {
			return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
		}
		return events, total, nil
	}

	var events []*models.AuditEvent
	offset := (page - 1) * pageSize
	if err := query.Order("event_time DESC").Limit(pageSize).Offset(offset).Find(&events).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}
	return events, total, nil
}

// GetRBACAuditLogs is not yet implemented; returns empty results.
func (ls *LocalStorage) GetRBACAuditLogs(_ context.Context, _ *storage.RBACAuditFilter) ([]*storage.RBACAuditLog, int64, error) {
	return nil, 0, nil
}

// CountImpersonatedActions counts impersonated audit events for actingAs by
// impersonator since `since`, excluding the impersonation.start/.end markers.
func (ls *LocalStorage) CountImpersonatedActions(ctx context.Context, actingAs, impersonator uint, since time.Time) (int64, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.AuditEvent{}).
		Where("impersonation = ? AND acting_as = ? AND impersonated_by = ? AND event_time >= ?", true, actingAs, impersonator, since).
		Where("event_type NOT IN ?", []string{"impersonation.start", "impersonation.end"}).
		Count(&n).Error
	return n, err
}

// --- Anomaly alerts ---

// anomalyDedupWindow bounds how long an equivalent alert suppresses duplicates.
// It matches RunDetection's 1-hour analysis window: re-running detection over
// the same window must not re-insert identical alerts, but a genuine later
// recurrence (a new access in a new window) still produces a fresh alert.
const anomalyDedupWindow = time.Hour

// CreateAnomalyAlert inserts an alert, idempotently. If an equivalent alert
// (same secret, type, actor, and IP) was already recorded within the dedup
// window, the insert is skipped and nil is returned — so re-running detection
// over the same window does not pile up duplicates.
func (ls *LocalStorage) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	cutoff := alert.DetectedAt
	if cutoff.IsZero() {
		cutoff = time.Now().UTC()
	}
	cutoff = cutoff.Add(-anomalyDedupWindow)

	var existing int64
	if err := ls.db.WithContext(ctx).Model(&models.AnomalyAlert{}).
		Where("secret_node_id = ? AND alert_type = ? AND accessed_by = ? AND ip_address = ? AND detected_at > ?",
			alert.SecretNodeID, alert.AlertType, alert.AccessedBy, alert.IPAddress, cutoff).
		Count(&existing).Error; err != nil {
		return err
	}
	if existing > 0 {
		return nil
	}
	return ls.db.WithContext(ctx).Create(alert).Error
}

// ListAnomalyAlerts returns alerts newest-first. acknowledged filters by state:
// nil returns all, &true only acknowledged, &false only unacknowledged.
func (ls *LocalStorage) ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	var alerts []models.AnomalyAlert
	query := ls.db.WithContext(ctx)
	if acknowledged != nil {
		query = query.Where("acknowledged = ?", *acknowledged)
	}
	result := query.Order("detected_at DESC").Find(&alerts)
	return alerts, result.Error
}

func (ls *LocalStorage) AcknowledgeAnomalyAlert(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Model(&models.AnomalyAlert{}).Where("id = ?", id).Update("acknowledged", true).Error
}

// GetDistinctActiveUserIDs returns the IDs of users who have logged in since the given time.
func (ls *LocalStorage) GetDistinctActiveUserIDs(ctx context.Context, since time.Time) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("event_type = ? AND event_time >= ?", "auth.login", since).
		Distinct("user_id").
		Pluck("user_id", &ids).Error
	return ids, err
}
