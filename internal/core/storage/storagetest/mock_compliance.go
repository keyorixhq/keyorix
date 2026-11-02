package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error) {
	args := m.Called(ctx, h)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LegalHold), args.Error(1)
}

func (m *MockStorage) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LegalHold), args.Error(1)
}

func (m *MockStorage) UpdateLegalHold(ctx context.Context, h *models.LegalHold) error {
	args := m.Called(ctx, h)
	return args.Error(0)
}

func (m *MockStorage) CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error) {
	args := m.Called(ctx, e)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RiskException), args.Error(1)
}

func (m *MockStorage) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	args := m.Called(ctx, activeOnly)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RiskException), args.Error(1)
}

func (m *MockStorage) GetRiskException(ctx context.Context, id uint) (*models.RiskException, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RiskException), args.Error(1)
}

func (m *MockStorage) RevokeRiskExceptionIfNotRevoked(ctx context.Context, e *models.RiskException) (bool, error) {
	args := m.Called(ctx, e)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ApproveRiskExceptionIfPending(ctx context.Context, e *models.RiskException) (bool, error) {
	args := m.Called(ctx, e)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	args := m.Called(ctx, a)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) ReconcileExpiredBreakGlassActivation(ctx context.Context, projectID, userID uint) error {
	args := m.Called(ctx, projectID, userID)
	return args.Error(0)
}

func (m *MockStorage) RevokeBreakGlassActivation(ctx context.Context, id, revokedBy, revokedByMachineID uint, revokedAt time.Time) error {
	args := m.Called(ctx, id, revokedBy, revokedByMachineID, revokedAt)
	return args.Error(0)
}

func (m *MockStorage) ReviewBreakGlassActivation(ctx context.Context, id, reviewerID uint, note string, reviewedAt time.Time) error {
	args := m.Called(ctx, id, reviewerID, note, reviewedAt)
	return args.Error(0)
}

func (m *MockStorage) ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) SettleBreakGlassOwedAudit(ctx context.Context, id uint, settledAt time.Time) (bool, error) {
	args := m.Called(ctx, id, settledAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListUnsettledBreakGlassActivations(ctx context.Context) ([]*models.BreakGlassActivation, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.BreakGlassActivation), args.Error(1)
}
