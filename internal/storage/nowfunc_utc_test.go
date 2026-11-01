package storage

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// SQLITE-UTC-NOWFUNC-1 items 1-2, storage level: what gormConfig's NowFunc does
// and does not cover. The host-zone end-to-end proof is
// server/http TestGormNowFunc_StoresUTCOnNonUTCHost_*.

func storedCreatedAt(t *testing.T, db *gorm.DB, table string, id uint) string {
	t.Helper()
	var typ, val sql.NullString
	row := db.Raw("SELECT typeof(created_at), created_at FROM "+table+" WHERE id = ?", id).Row()
	require.NoError(t, row.Scan(&typ, &val))
	require.True(t, val.Valid)
	return typ.String + ":" + val.String
}

func TestGormConfigNowFuncIsUTC(t *testing.T) {
	got := gormConfig().NowFunc()
	require.Same(t, time.UTC, got.Location(), "NowFunc must return a UTC time, whatever the host zone")
}

// The explicit `CreatedAt: c.now().UTC()` in pat.go and machine_token.go stay:
// GORM's NowFunc only stamps a ZERO CreatedAt, PersonalAccessToken has no hook
// that converts CreatedAt, and core assigns c.now() (host zone, and a fake clock
// in tests). So NowFunc does not make those conversions redundant -- this test
// is the proof, and fails if either half of that claim changes.
func TestNowFuncDoesNotCoverExplicitCreatedAt(t *testing.T) {
	db := sqlitetest.OpenWithDialector(t, "nowfunc_", sqlite.Open, gormConfig())
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}))

	stamped := &models.PersonalAccessToken{UserID: 1, Name: "stamped", TokenHash: "h1", TokenPrefix: "kx_pat_aaaaaa"}
	require.NoError(t, db.Create(stamped).Error)
	require.False(t, stamped.CreatedAt.IsZero(), "GORM must stamp a zero CreatedAt")
	require.Same(t, time.UTC, stamped.CreatedAt.Location())
	require.True(t, strings.HasPrefix(storedCreatedAt(t, db, "personal_access_tokens", stamped.ID), "text:"), "stored as text")
	require.True(t, strings.HasSuffix(storedCreatedAt(t, db, "personal_access_tokens", stamped.ID), "Z"), "NowFunc-stamped created_at is stored UTC")

	zone := time.FixedZone("OT", 14*3600)
	explicit := &models.PersonalAccessToken{UserID: 1, Name: "explicit", TokenHash: "h2", TokenPrefix: "kx_pat_bbbbbb", CreatedAt: time.Now().In(zone)}
	require.NoError(t, db.Create(explicit).Error)
	require.Contains(t, storedCreatedAt(t, db, "personal_access_tokens", explicit.ID), "+1400 OT",
		"an explicitly assigned non-UTC CreatedAt is stored as given: the `.UTC()` at the assignment is load-bearing")
}
