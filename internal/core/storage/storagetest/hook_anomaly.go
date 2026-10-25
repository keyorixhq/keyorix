package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	if hk := hs.h.CreateAnomalyAlert; hk != nil {
		return hk(hs.Storage, ctx, alert)
	}
	return hs.Storage.CreateAnomalyAlert(ctx, alert)
}
