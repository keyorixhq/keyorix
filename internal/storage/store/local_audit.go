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
		if filter.StartTime != nil {
			query = query.Where("event_time >= ?", *filter.StartTime)
		}
		if filter.EndTime != nil {
			query = query.Where("event_time <= ?", *filter.EndTime)
		}
		if filter.Success != nil {
			query = query.Where("success = ?", *filter.Success)
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
