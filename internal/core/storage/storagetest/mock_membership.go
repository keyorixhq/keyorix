package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) ListProjectMembers(_ context.Context, _ uint) ([]storage.ProjectMember, error) {
	return nil, nil
}

func (m *MockStorage) ListUserProjectMembershipsByUserIDs(ctx context.Context, ids []uint) (map[uint][]*models.ProjectMembership, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]*models.ProjectMembership), args.Error(1)
}

// Project membership lifecycle (ADR-022).
func (m *MockStorage) CreateProjectMembership(ctx context.Context, pm *models.ProjectMembership) (*models.ProjectMembership, error) {
	args := m.Called(ctx, pm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) TransitionProjectMembershipState(ctx context.Context, pm *models.ProjectMembership, fromState string) (bool, error) {
	args := m.Called(ctx, pm, fromState)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error) {
	args := m.Called(ctx, projectID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	args := m.Called(ctx, userIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]storage.MembershipCounts), args.Error(1)
}
