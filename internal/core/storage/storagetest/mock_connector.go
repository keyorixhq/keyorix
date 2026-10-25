package storagetest

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Keyorix Connect per-reference grants (ADR-045) — core enforcement is tested against
// real SQLite, so these mock stubs just satisfy the interface.
func (m *MockStorage) ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListConnectRefGrantsByConnector" {
			args := m.Called(ctx, connector)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.ConnectRefGrant), args.Error(1)
		}
	}
	return nil, nil
}
func (m *MockStorage) ListConnectRefGrants(_ context.Context) ([]*models.ConnectRefGrant, error) {
	return nil, nil
}
func (m *MockStorage) CreateConnectRefGrant(_ context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error) {
	return grant, nil
}
func (m *MockStorage) DeleteConnectRefGrant(_ context.Context, _ uint) error {
	return nil
}

// ADR-082 branch 2: connector project-binding storage — core enforcement is tested
// against real SQLite (connect_rbac_test.go, connect_ownership_test.go), so these
// mock stubs just satisfy the interface. GetProjectByName/GetConnectorProjectBinding
// default to "not found" (the substring convention every caller of these checks
// against) rather than a zero value, since a zero-value *models.Project/
// *models.ConnectorProjectBinding would misrepresent a real, resolvable result.
func (m *MockStorage) GetProjectByName(_ context.Context, _ string) (*models.Project, error) {
	return nil, fmt.Errorf("project not found")
}
func (m *MockStorage) GetConnectorProjectBinding(_ context.Context, _ string) (*models.ConnectorProjectBinding, error) {
	return nil, fmt.Errorf("connector project binding not found")
}
func (m *MockStorage) CreateConnectorProjectBinding(_ context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error) {
	return binding, nil
}
func (m *MockStorage) ListConnectorProjectBindings(_ context.Context) ([]*models.ConnectorProjectBinding, error) {
	return nil, nil
}
