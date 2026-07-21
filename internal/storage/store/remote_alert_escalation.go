// remote_alert_escalation.go — RemoteStorage stubs for alert escalation policy
// management. The REST API (/api/v1/alert-escalation-policies) is the remote
// surface; these methods are never invoked directly by a remote-storage caller.
// All stubs are classified in remote_alert_escalation_completeness_test.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateAlertEscalationPolicy(_ context.Context, _ *models.AlertEscalationPolicy) error {
	return remoteUnsupported("CreateAlertEscalationPolicy")
}

func (rs *RemoteStorage) GetAlertEscalationPolicy(_ context.Context, _ uint) (*models.AlertEscalationPolicy, error) {
	return nil, remoteUnsupported("GetAlertEscalationPolicy")
}

func (rs *RemoteStorage) ListAlertEscalationPolicies(_ context.Context) ([]models.AlertEscalationPolicy, error) {
	return nil, remoteUnsupported("ListAlertEscalationPolicies")
}

func (rs *RemoteStorage) UpdateAlertEscalationPolicy(_ context.Context, _ *models.AlertEscalationPolicy) error {
	return remoteUnsupported("UpdateAlertEscalationPolicy")
}

func (rs *RemoteStorage) DeleteAlertEscalationPolicy(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteAlertEscalationPolicy")
}

func (rs *RemoteStorage) ListUnacknowledgedAnomalyAlertsBefore(_ context.Context, _ time.Time) ([]models.AnomalyAlert, error) {
	return nil, remoteUnsupported("ListUnacknowledgedAnomalyAlertsBefore")
}
