package sqlitetest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TZ-RESIDUE-1 item 4 (#3914): production opens with NowFunc returning UTC
// (internal/storage/factory.go gormConfig); the harness must too, or store and core tests under a
// non-UTC TZ model the old host-zone created_at / updated_at / deleted_at stamping. The check is
// the zone the stamp carries, so it is red only under a non-UTC TZ (run with TZ=Asia/Tokyo).
func TestOpen_StampsWithUTCNowFunc(t *testing.T) {
	require.Same(t, time.UTC, Open(t, "nowfunc_").NowFunc().Location(), "the default harness config stamps in UTC")

	custom := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("X", 3600))
	db := OpenWithConfig(t, "nowfunc_", &gorm.Config{NowFunc: func() time.Time { return custom }})
	require.True(t, db.NowFunc().Equal(custom), "a caller-supplied NowFunc is kept")
}
