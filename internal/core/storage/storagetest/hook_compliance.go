package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	if hk := hs.h.GetActiveLegalHold; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.GetActiveLegalHold(ctx)
}

func (hs *HookStore) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	if hk := hs.h.ListRiskExceptions; hk != nil {
		return hk(hs.Storage, ctx, activeOnly)
	}
	return hs.Storage.ListRiskExceptions(ctx, activeOnly)
}

func (hs *HookStore) ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error) {
	if hk := hs.h.ListUnreviewedBreakGlassActivationsBefore; hk != nil {
		return hk(hs.Storage, ctx, cutoff)
	}
	return hs.Storage.ListUnreviewedBreakGlassActivationsBefore(ctx, cutoff)
}
