// remote_risk_exceptions.go — risk exceptions for RemoteStorage. Processed
// server-side; stubs here. See local_risk_exceptions.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateRiskException(_ context.Context, _ *models.RiskException) (*models.RiskException, error) {
	return nil, remoteUnsupported("CreateRiskException")
}

func (rs *RemoteStorage) ListRiskExceptions(_ context.Context, _ bool) ([]*models.RiskException, error) {
	return nil, remoteUnsupported("ListRiskExceptions")
}

func (rs *RemoteStorage) GetRiskException(_ context.Context, _ uint) (*models.RiskException, error) {
	return nil, remoteUnsupported("GetRiskException")
}

func (rs *RemoteStorage) UpdateRiskException(_ context.Context, _ *models.RiskException) error {
	return remoteUnsupported("UpdateRiskException")
}
