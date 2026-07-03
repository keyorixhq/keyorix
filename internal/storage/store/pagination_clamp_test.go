package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestClampPageSize pins the defense-in-depth ceiling LocalStorage applies to every
// paginated query, independent of whatever clamp (if any) the caller already applied.
func TestClampPageSize(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"typical page size unaffected", 20, 20},
		{"exactly at the ceiling unaffected", maxStoragePageSize, maxStoragePageSize},
		{"one over the ceiling clamped down", maxStoragePageSize + 1, maxStoragePageSize},
		{"wildly oversized clamped down", 1 << 30, maxStoragePageSize},
		{"zero passed through (caller's own default applies)", 0, 0},
		{"negative passed through (caller's own default applies)", -1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clampPageSize(tc.in))
		})
	}
}

// TestListSecrets_PageSizeClampedAtStorage confirms a future caller that forgets to
// clamp PageSize itself (bypassing the ≤100 clamp every current HTTP/gRPC handler
// applies before reaching storage) cannot force an unbounded SQL LIMIT — the storage
// layer's own ceiling still applies, and the call succeeds rather than erroring or
// hanging on a hostile/overflowed value.
func TestListSecrets_PageSizeClampedAtStorage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	for i := 0; i < 5; i++ {
		require.NoError(t, db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("secret-%d", i),
			IsSecret: true, Type: "api_key", Status: "active",
		}).Error)
	}

	secrets, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		Page: 1, PageSize: 1 << 30, // a caller that forgot to clamp
	})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, secrets, 5)
}
