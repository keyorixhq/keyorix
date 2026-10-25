package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateProject(_ context.Context, project *models.Project) (*models.Project, error) {
	return project, nil
}

func (m *MockStorage) CreateEnvironment(_ context.Context, env *models.Environment) (*models.Environment, error) {
	return env, nil
}

func (m *MockStorage) ListProjects(_ context.Context) ([]*models.Project, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectsWithCounts(_ context.Context, _ bool) ([]storage.ProjectWithCounts, error) {
	return nil, nil
}

func (m *MockStorage) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "GetProject" {
			args := m.Called(ctx, id)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).(*models.Project), args.Error(1)
		}
	}
	return &models.Project{}, nil
}

func (m *MockStorage) UpdateProjectFields(_ context.Context, _ uint, _, _ string, _ *bool, _ time.Time) (bool, error) {
	return true, nil
}

func (m *MockStorage) DeleteProject(_ context.Context, _ uint) error {
	return nil
}

// DeleteProjectIfEmpty defaults to "empty, delete succeeded" (0 blocking secrets) —
// the same trivial-success default DeleteProject above uses. Tests exercising the
// #528 guard behavior use catalog_delete_project_test.go's dedicated spies instead.
func (m *MockStorage) DeleteProjectIfEmpty(_ context.Context, _ uint) (int, error) {
	return 0, nil
}

func (m *MockStorage) RestoreProject(_ context.Context, _ uint) (int, int, error) {
	return 0, 0, nil
}

// The #3433 machine-identity cascade steps: this mock holds no machine identities.
func (m *MockStorage) SuspendMachineIdentitiesForDeletedProject(_ context.Context, _ uint) ([]*models.MachineIdentity, error) {
	return nil, nil
}

func (m *MockStorage) ReactivateMachineIdentitiesForRestoredProject(_ context.Context, _ uint, _ time.Time) ([]*models.MachineIdentity, error) {
	return nil, nil
}

func (m *MockStorage) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	if len(m.ExpectedCalls) == 0 {
		return nil, nil
	}
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListEnvironmentsByProject" {
			args := m.Called(ctx, projectID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Environment), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProjectIncludingDeleted(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) GetEnvironment(_ context.Context, id uint) (*models.Environment, error) {
	return &models.Environment{ID: id, ProjectID: 1, Name: "test"}, nil
}

func (m *MockStorage) DeleteEnvironment(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) RestoreEnvironment(_ context.Context, _, _ uint) error {
	return nil
}
