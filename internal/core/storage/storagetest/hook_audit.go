package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) ClaimPendingAuditEvent(ctx context.Context, id uint) (bool, error) {
	if hk := hs.h.ClaimPendingAuditEvent; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.ClaimPendingAuditEvent(ctx, id)
}

func (hs *HookStore) CountPendingAuditEvents(ctx context.Context) (int64, error) {
	if hk := hs.h.CountPendingAuditEvents; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.CountPendingAuditEvents(ctx)
}

func (hs *HookStore) OldestPendingAuditEventAt(ctx context.Context) (time.Time, bool, error) {
	if hk := hs.h.OldestPendingAuditEventAt; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.OldestPendingAuditEventAt(ctx)
}

func (hs *HookStore) CreatePendingAuditEvent(ctx context.Context, p *models.PendingAuditEvent) error {
	if hk := hs.h.CreatePendingAuditEvent; hk != nil {
		return hk(hs.Storage, ctx, p)
	}
	return hs.Storage.CreatePendingAuditEvent(ctx, p)
}

func (hs *HookStore) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	if hk := hs.h.CreateSecretAccessLog; hk != nil {
		return hk(hs.Storage, ctx, log)
	}
	return hs.Storage.CreateSecretAccessLog(ctx, log)
}

func (hs *HookStore) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	if hk := hs.h.GetAuditLogs; hk != nil {
		return hk(hs.Storage, ctx, filter)
	}
	return hs.Storage.GetAuditLogs(ctx, filter)
}

func (hs *HookStore) LastUserRoleManagementActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	if hk := hs.h.LastUserRoleManagementActivity; hk != nil {
		return hk(hs.Storage, ctx, projectID, since)
	}
	return hs.Storage.LastUserRoleManagementActivity(ctx, projectID, since)
}

func (hs *HookStore) LastUserSecretDeletionActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	if hk := hs.h.LastUserSecretDeletionActivity; hk != nil {
		return hk(hs.Storage, ctx, projectID, since)
	}
	return hs.Storage.LastUserSecretDeletionActivity(ctx, projectID, since)
}

func (hs *HookStore) LastUserSecretWriteActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	if hk := hs.h.LastUserSecretWriteActivity; hk != nil {
		return hk(hs.Storage, ctx, projectID, since)
	}
	return hs.Storage.LastUserSecretWriteActivity(ctx, projectID, since)
}

func (hs *HookStore) ListPendingAuditEvents(ctx context.Context, afterID uint, limit int) ([]*models.PendingAuditEvent, error) {
	if hk := hs.h.ListPendingAuditEvents; hk != nil {
		return hk(hs.Storage, ctx, afterID, limit)
	}
	return hs.Storage.ListPendingAuditEvents(ctx, afterID, limit)
}

func (hs *HookStore) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	if hk := hs.h.ListSecretAccessLogs; hk != nil {
		return hk(hs.Storage, ctx, secretID, since)
	}
	return hs.Storage.ListSecretAccessLogs(ctx, secretID, since)
}

func (hs *HookStore) ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error) {
	if hk := hs.h.ListSecretIDsAccessedSince; hk != nil {
		return hk(hs.Storage, ctx, since)
	}
	return hs.Storage.ListSecretIDsAccessedSince(ctx, since)
}

func (hs *HookStore) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	if hk := hs.h.LogAuditEvent; hk != nil {
		return hk(hs.Storage, ctx, event)
	}
	return hs.Storage.LogAuditEvent(ctx, event)
}

func (hs *HookStore) LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	if hk := hs.h.LogAuditEventWithAccessLog; hk != nil {
		return hk(hs.Storage, ctx, event, accessLog)
	}
	return hs.Storage.LogAuditEventWithAccessLog(ctx, event, accessLog)
}

func (hs *HookStore) RecordPendingAuditEventFailure(ctx context.Context, id uint, reason string) error {
	if hk := hs.h.RecordPendingAuditEventFailure; hk != nil {
		return hk(hs.Storage, ctx, id, reason)
	}
	return hs.Storage.RecordPendingAuditEventFailure(ctx, id, reason)
}

func (hs *HookStore) VerifyAuditChain(ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	if hk := hs.h.VerifyAuditChain; hk != nil {
		return hk(hs.Storage, ctx, anchor)
	}
	return hs.Storage.VerifyAuditChain(ctx, anchor)
}

func (hs *HookStore) VerifyAuditChainSegment(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	if hk := hs.h.VerifyAuditChainSegment; hk != nil {
		return hk(hs.Storage, ctx, seg)
	}
	return hs.Storage.VerifyAuditChainSegment(ctx, seg)
}
