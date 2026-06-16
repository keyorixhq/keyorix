package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newConnectGrantStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ConnectRefGrant{}))
	return NewLocalStorage(db)
}

func TestConnectRefGrants_CRUDAndScoping(t *testing.T) {
	ls := newConnectGrantStore(t)
	ctx := context.Background()

	_, err := ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: 5, Connector: "aws", RefPrefix: "metrics/"})
	require.NoError(t, err)
	_, err = ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: 6, Connector: "aws", RefPrefix: "db/"})
	require.NoError(t, err)
	g3, err := ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: 5, Connector: "gcp", RefPrefix: ""})
	require.NoError(t, err)

	// By-connector returns only that connector's grants (the enforcement path).
	aws, err := ls.ListConnectRefGrantsByConnector(ctx, "aws")
	require.NoError(t, err)
	assert.Len(t, aws, 2)
	for _, g := range aws {
		assert.Equal(t, "aws", g.Connector)
	}

	// List-all returns every grant.
	all, err := ls.ListConnectRefGrants(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// Delete removes one; the rest remain.
	require.NoError(t, ls.DeleteConnectRefGrant(ctx, g3.ID))
	gcp, err := ls.ListConnectRefGrantsByConnector(ctx, "gcp")
	require.NoError(t, err)
	assert.Empty(t, gcp)
}

func TestConnectRefGrants_UniqueTriple(t *testing.T) {
	ls := newConnectGrantStore(t)
	ctx := context.Background()
	_, err := ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: 5, Connector: "aws", RefPrefix: "metrics/"})
	require.NoError(t, err)
	// Re-creating the identical (role, connector, prefix) triple conflicts on the
	// unique index.
	_, err = ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: 5, Connector: "aws", RefPrefix: "metrics/"})
	require.Error(t, err)
}
