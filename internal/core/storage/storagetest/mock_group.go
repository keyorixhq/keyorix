package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) ListAllUserGroupMemberships(ctx context.Context) ([]storage.UserGroupMembership, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UserGroupMembership), args.Error(1)
}

func (m *MockStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	args := m.Called(ctx, group)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	if !m.mockHasExpectation("GetGroup") {
		return nil, errMockLookupNotStubbed
	}
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) UpdateGroupFields(ctx context.Context, id uint, name, nameFolded, description *string, updatedAt time.Time) (bool, error) {
	a := m.Called(ctx, id, name, nameFolded, description, updatedAt)
	return a.Bool(0), a.Error(1)
}

func (m *MockStorage) DeleteGroup(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RestoreGroup(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) ListGroupsPage(ctx context.Context, offset, pageSize int) ([]*models.Group, int64, error) {
	args := m.Called(ctx, offset, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.Group), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error {
	args := m.Called(ctx, userID, groupID, projectID)
	return args.Error(0)
}

func (m *MockStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error {
	return m.Called(ctx, userID, groupID, projectID).Error(0)
}

func (m *MockStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) ListGroupMembersAt(ctx context.Context, groupID uint, scope storage.Scope) ([]*models.User, error) {
	args := m.Called(ctx, groupID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) ListGroupMembersByGroupIDs(ctx context.Context, groupIDs []uint) (map[uint][]*models.User, error) {
	args := m.Called(ctx, groupIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]*models.User), args.Error(1)
}
