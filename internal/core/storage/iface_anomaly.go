package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AnomalyStore is the Storage slice for anomaly detection configuration and alerts.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type AnomalyStore interface {
	// GetAnomalyConfig retrieves the single anomaly config row, or returns sensible
	// defaults if no row has been saved yet.
	GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error)
	SaveAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord) error
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	// AcknowledgeAnomalyAlert marks an alert acknowledged and stamps who did it and
	// when directly on the row (#217), alongside the separate audit event the core
	// layer emits.
	AcknowledgeAnomalyAlert(ctx context.Context, id, actorID uint, at time.Time) error
	// ListUnalertedAnomalyAlerts returns alerts not yet pushed out (alerted=false),
	// and MarkAnomalyAlertAlerted flags one as pushed — for proactive alerting.
	ListUnalertedAnomalyAlerts(ctx context.Context) ([]models.AnomalyAlert, error)
	MarkAnomalyAlertAlerted(ctx context.Context, id uint) error

	// ListUnacknowledgedAnomalyAlertsBefore returns unacknowledged anomaly alerts
	// whose created_at (detected_at) is older than the given threshold.
	ListUnacknowledgedAnomalyAlertsBefore(ctx context.Context, threshold time.Time) ([]models.AnomalyAlert, error)
}
