package store

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// CompareAndSetSystemMetadata (AUDIT-HIGHWATER-CAS-1) writes only over the
// value the caller read, or into an absent row, and reports a lost race as
// swapped=false with no error; the row then keeps the other writer's value.
func TestCompareAndSetSystemMetadata(t *testing.T) {
	backends := []struct {
		name string
		open func(t *testing.T) *gorm.DB
	}{
		{"sqlite", func(t *testing.T) *gorm.DB {
			return sqlitetest.OpenWithDialector(t, "smcas_", sqlite.Open, &gorm.Config{})
		}},
		{"postgres", func(t *testing.T) *gorm.DB {
			dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
			if dsn == "" {
				t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
			}
			db, err := gorm.Open(postgres.Open(pgdsn.IsolatedDatabase(t, dsn, "store_smcas")), &gorm.Config{})
			require.NoError(t, err)
			t.Cleanup(func() {
				if sqlDB, e := db.DB(); e == nil {
					_ = sqlDB.Close()
				}
			})
			return db
		}},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
			ls := NewLocalStorage(db)
			ctx := context.Background()
			get := func() (string, bool) {
				v, ok, err := ls.GetSystemMetadata(ctx, "k")
				require.NoError(t, err)
				return v, ok
			}

			ok, err := ls.CompareAndSetSystemMetadata(ctx, "k", "", false, "one")
			require.NoError(t, err)
			assert.True(t, ok, "insert into an absent row")

			ok, err = ls.CompareAndSetSystemMetadata(ctx, "k", "", false, "other")
			require.NoError(t, err)
			assert.False(t, ok, "an insert loses when the row appeared since the read")
			v, _ := get()
			assert.Equal(t, "one", v)

			ok, err = ls.CompareAndSetSystemMetadata(ctx, "k", "stale", true, "other")
			require.NoError(t, err)
			assert.False(t, ok, "an update loses when the row changed since the read")
			v, _ = get()
			assert.Equal(t, "one", v)

			ok, err = ls.CompareAndSetSystemMetadata(ctx, "k", "one", true, "two")
			require.NoError(t, err)
			assert.True(t, ok)
			ok, err = ls.CompareAndSetSystemMetadata(ctx, "k", "two", true, "two")
			require.NoError(t, err)
			assert.True(t, ok, "rewriting the same value is a swap")
			v, found := get()
			assert.True(t, found)
			assert.Equal(t, "two", v)

			ok, err = ls.CompareAndSetSystemMetadata(ctx, "absent", "x", true, "y")
			require.NoError(t, err)
			assert.False(t, ok, "an update of a row that was deleted since the read loses")
			_, found, err = ls.GetSystemMetadata(ctx, "absent")
			require.NoError(t, err)
			assert.False(t, found, "and creates nothing")
		})
	}
}
