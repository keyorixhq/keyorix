// remote_break_glass.go — break-glass activations for RemoteStorage. Processed
// server-side; stubs here. See local_break_glass.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateBreakGlassActivation(_ context.Context, _ *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	return nil, remoteUnsupported("CreateBreakGlassActivation")
}

func (rs *RemoteStorage) GetBreakGlassActivation(_ context.Context, _ uint) (*models.BreakGlassActivation, error) {
	return nil, remoteUnsupported("GetBreakGlassActivation")
}

func (rs *RemoteStorage) ListBreakGlassActivations(_ context.Context, _ uint) ([]*models.BreakGlassActivation, error) {
	return nil, remoteUnsupported("ListBreakGlassActivations")
}

func (rs *RemoteStorage) UpdateBreakGlassActivation(_ context.Context, _ *models.BreakGlassActivation) error {
	return remoteUnsupported("UpdateBreakGlassActivation")
}
