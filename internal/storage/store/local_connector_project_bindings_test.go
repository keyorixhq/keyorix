package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newConnectorProjectBindingStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ConnectorProjectBinding{}))
	return NewLocalStorage(db)
}

func TestConnectorProjectBinding_CreateGetList(t *testing.T) {
	ls := newConnectorProjectBindingStore(t)
	ctx := context.Background()

	created, err := ls.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "k8s-prod", ProjectID: 5, ProjectName: "prod",
	})
	require.NoError(t, err)
	assert.NotZero(t, created.ID)

	got, err := ls.GetConnectorProjectBinding(ctx, "k8s-prod")
	require.NoError(t, err)
	assert.Equal(t, uint(5), got.ProjectID)
	assert.Equal(t, "prod", got.ProjectName)

	_, err = ls.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "k8s-staging", ProjectID: 6, ProjectName: "staging",
	})
	require.NoError(t, err)

	all, err := ls.ListConnectorProjectBindings(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestConnectorProjectBinding_GetNotFound(t *testing.T) {
	ls := newConnectorProjectBindingStore(t)
	binding, err := ls.GetConnectorProjectBinding(context.Background(), "does-not-exist")
	require.Error(t, err)
	assert.Nil(t, binding)
	assert.Contains(t, err.Error(), "not found")
}

// Connector has a unique index — a second binding for an already-bound
// connector must conflict, matching CreateConnectorProjectBinding's own doc
// comment ("callers must check GetConnectorProjectBinding first").
func TestConnectorProjectBinding_DuplicateConnectorConflicts(t *testing.T) {
	ls := newConnectorProjectBindingStore(t)
	ctx := context.Background()

	_, err := ls.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "k8s-prod", ProjectID: 5, ProjectName: "prod",
	})
	require.NoError(t, err)

	_, err = ls.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "k8s-prod", ProjectID: 9, ProjectName: "other",
	})
	require.Error(t, err)
}

func TestConnectorProjectBinding_ListEmpty(t *testing.T) {
	ls := newConnectorProjectBindingStore(t)
	all, err := ls.ListConnectorProjectBindings(context.Background())
	require.NoError(t, err)
	assert.Empty(t, all)
}
