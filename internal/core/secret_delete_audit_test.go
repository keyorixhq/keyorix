package core

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// #2951 item 3: a secret delete is a SOFT delete (restorable, versions kept), and
// it can break the dependency of other secrets. The audit entry must say so
// instead of only "deleted secret X", while keeping the "User <u> deleted secret
// <name>" prefix that the dashboard and audit search parse.
func TestLogSecretDeletedWithProject_DescribesSoftDeleteAndDependents(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	var logged *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Run(func(a mock.Arguments) { logged = a.Get(1).(*models.AuditEvent) }).Return(nil)
	ms.On("CreateSecretAccessLog", mock.Anything, mock.Anything).Return(nil)
	ms.On("GetSecretVersions", mock.Anything, uint(16)).Return([]*models.SecretVersion{{}, {}, {}, {}, {}}, nil)
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(100)).Return([]*models.SecretDependency{
		{DependentSecretID: 20, DependsOnSecretID: 16}, // 20 depends on the deleted secret: affected
		{DependentSecretID: 16, DependsOnSecretID: 30}, // the deleted secret's own edge: nobody affected
	}, nil)
	ms.On("GetSecret", mock.Anything, uint(20)).Return(&models.SecretNode{ID: 20, Name: "app-config"}, nil)
	c := NewKeyorixCore(ms)

	c.LogSecretDeletedWithProject(context.Background(), 1, 16, 100, "alice", "db-pass", "1.2.3.4", "ua")

	if logged == nil {
		t.Fatal("no audit event written")
	}
	d := logged.Description
	assert.True(t, strings.HasPrefix(d, "User alice deleted secret db-pass"), d)
	assert.Contains(t, d, "soft delete")
	assert.Contains(t, d, "restor")
	assert.Contains(t, d, "5 version(s) kept")
	assert.Contains(t, d, "app-config")
	assert.NotContains(t, d, "30", "the deleted secret's own dependency does not affect anyone")
	assert.Equal(t, "db-pass", extractSecretName(d), "name parsing (dashboard) must ignore the soft-delete note")
}

func TestLogSecretDeletedWithProject_NoDependentsNoDependentClause(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	var logged *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Run(func(a mock.Arguments) { logged = a.Get(1).(*models.AuditEvent) }).Return(nil)
	ms.On("CreateSecretAccessLog", mock.Anything, mock.Anything).Return(nil)
	ms.On("GetSecretVersions", mock.Anything, uint(16)).Return([]*models.SecretVersion{{}}, nil)
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(100)).Return([]*models.SecretDependency{}, nil)
	c := NewKeyorixCore(ms)

	c.LogSecretDeletedWithProject(context.Background(), 1, 16, 100, "alice", "db-pass", "1.2.3.4", "ua")

	assert.Contains(t, logged.Description, "1 version(s) kept")
	assert.NotContains(t, logged.Description, "dependen")
}
