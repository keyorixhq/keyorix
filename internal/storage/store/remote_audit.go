// remote_audit.go — Audit log and anomaly alert operations for RemoteStorage.
//
// Covers: LogAuditEvent, CreateSecretAccessLog (no-op), GetAuditLogs,
//
//	GetRBACAuditLogs, ListSecretAccessLogs (unsupported),
//	CreateAnomalyAlert, ListAnomalyAlerts, AcknowledgeAnomalyAlert.
//
// Access logging and anomaly detection are handled server-side in remote mode;
// most write operations are no-ops or return a clear error.
// For the local (GORM) equivalent see local_audit.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// LogAuditEvent logs an audit event via remote API.
func (rs *RemoteStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	resp, err := rs.client.Post(ctx, "/api/v1/audit/events", event)
	if err != nil {
		return fmt.Errorf("failed to log audit event: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("log audit event failed: %s", resp.Error.Error())
	}
	return nil
}

// CreateSecretAccessLog is a no-op in remote mode; access logging is handled server-side.
func (rs *RemoteStorage) CreateSecretAccessLog(_ context.Context, _ *models.SecretAccessLog) error {
	return nil
}

// GetAuditLogs retrieves audit events with optional filtering via remote API.
func (rs *RemoteStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	path := buildAuditFilterPath(filter)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}
	if !resp.Success {
		return nil, 0, fmt.Errorf("get audit logs failed: %s", resp.Error.Error())
	}
	var result struct {
		Events []*models.AuditEvent `json:"events"`
		Total  int64                `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Events, result.Total, nil
}

// buildAuditFilterPath constructs the /api/v1/audit/events query string.
func buildAuditFilterPath(filter *storage.AuditFilter) string {
	if filter == nil {
		return "/api/v1/audit/events"
	}
	params := newQueryBuilder()
	params.addUint("user_id", filter.UserID)
	params.addString("action", filter.Action)
	params.addString("resource", filter.Resource)
	params.addBool("success", filter.Success)
	params.addTime("start_time", filter.StartTime)
	params.addTime("end_time", filter.EndTime)
	params.addPage(filter.Page, filter.PageSize)
	return "/api/v1/audit/events" + params.String()
}

// GetRBACAuditLogs retrieves RBAC audit logs with optional filtering via remote API.
func (rs *RemoteStorage) GetRBACAuditLogs(ctx context.Context, filter *storage.RBACAuditFilter) ([]*storage.RBACAuditLog, int64, error) {
	path := buildRBACAuditFilterPath(filter)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get RBAC audit logs: %w", err)
	}
	if !resp.Success {
		return nil, 0, fmt.Errorf("get RBAC audit logs failed: %s", resp.Error.Error())
	}
	var result struct {
		Logs  []*storage.RBACAuditLog `json:"logs"`
		Total int64                   `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Logs, result.Total, nil
}

// buildRBACAuditFilterPath constructs the /api/v1/audit/rbac query string.
func buildRBACAuditFilterPath(filter *storage.RBACAuditFilter) string {
	if filter == nil {
		return "/api/v1/audit/rbac"
	}
	params := newQueryBuilder()
	params.addUint("user_id", filter.UserID)
	params.addString("action", filter.Action)
	params.addString("target_type", filter.TargetType)
	params.addUint("target_id", filter.TargetID)
	params.addTime("start_time", filter.StartTime)
	params.addTime("end_time", filter.EndTime)
	params.addPage(filter.Page, filter.PageSize)
	return "/api/v1/audit/rbac" + params.String()
}

// ListSecretAccessLogs is not available in remote mode; server handles access logs.
func (rs *RemoteStorage) ListSecretAccessLogs(_ context.Context, _ uint, _ time.Time) ([]models.SecretAccessLog, error) {
	return nil, fmt.Errorf("ListSecretAccessLogs not available in remote mode")
}

// CreateAnomalyAlert is not available in remote mode; anomaly detection is server-side.
func (rs *RemoteStorage) CreateAnomalyAlert(_ context.Context, _ *models.AnomalyAlert) error {
	return fmt.Errorf("CreateAnomalyAlert not available in remote mode")
}

// ListAnomalyAlerts is not available in remote mode.
func (rs *RemoteStorage) ListAnomalyAlerts(_ context.Context, _ bool) ([]models.AnomalyAlert, error) {
	return nil, fmt.Errorf("ListAnomalyAlerts not available in remote mode")
}

// AcknowledgeAnomalyAlert is not available in remote mode.
func (rs *RemoteStorage) AcknowledgeAnomalyAlert(_ context.Context, _ uint) error {
	return fmt.Errorf("AcknowledgeAnomalyAlert not available in remote mode")
}
