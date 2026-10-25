package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) ListMachineCredentialUsageByMachineIDs(ctx context.Context, ids []uint) (map[uint][]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]*models.MachineIdentityCredential), args.Error(1)
}

// Machine identities (ADR-023).
func (m *MockStorage) CreateMachineIdentity(ctx context.Context, mi *models.MachineIdentity) (*models.MachineIdentity, error) {
	args := m.Called(ctx, mi)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	a := m.Called(ctx, id)
	v, _ := a.Get(0).(*models.MachineIdentity)
	return v, a.Error(1)
}

func (m *MockStorage) TransitionMachineIdentityState(ctx context.Context, mi *models.MachineIdentity, fromState string) (bool, error) {
	args := m.Called(ctx, mi, fromState)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func (m *MockStorage) CountStaleMachineIdentitiesByProject(ctx context.Context, projectIDs []uint, olderThan time.Time) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs, olderThan)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetMachineIdentityCredentialWithIdentityStateByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, string, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.String(1), args.Error(2)
}

func (m *MockStorage) GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) SetMachineIdentityCredentialClassification(ctx context.Context, credentialID uint, fromClassification, toClassification string) (bool, error) {
	args := m.Called(ctx, credentialID, fromClassification, toClassification)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error) {
	a := m.Called(ctx)
	v, _ := a.Get(0).(map[string]int)
	return v, a.Error(1)
}

func (m *MockStorage) RevokeMachineIdentityCredential(ctx context.Context, projectID, id uint) error {
	return m.Called(ctx, projectID, id).Error(0)
}

func (m *MockStorage) TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	// Best-effort on the auth hot path — tolerate tests that don't set an expectation.
	for _, c := range m.ExpectedCalls {
		if c.Method == "TouchMachineIdentityCredential" {
			return m.Called(ctx, id, usedAt, staleness).Error(0)
		}
	}
	return nil
}

func (m *MockStorage) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, machineID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	return m.Called(ctx, machineID, roleID, scope).Error(0)
}

func (m *MockStorage) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, machineID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) GetMachineRoleScopes(ctx context.Context, machineID uint) ([]storage.Scope, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.Scope), args.Error(1)
}

func (m *MockStorage) CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, b)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error) {
	args := m.Called(ctx, issuer, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) DeleteOIDCBinding(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	return storage.ComposeMachinePermissionAt(ctx, m, machineID, scope, permission)
}

func (m *MockStorage) ListExpiringMachineCredentials(ctx context.Context, cutoff time.Time) ([]models.MachineIdentityCredential, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.MachineIdentityCredential), args.Error(1)
}
