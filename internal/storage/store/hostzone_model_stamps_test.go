package store

// HOSTZONE-TIME-NOV-1 item 1, internal/storage half. Three writers stamp a persisted model's
// CreatedAt / UpdatedAt with time.Now() in the host zone, and the row goes in through a plain
// Create, which stores a non-zero timestamp as given (GORM's NowFunc is UTC but stamps only a zero
// field):
//
//   - models.ValidateShareRecord (CreateShareRecord): share_records.created_at and updated_at;
//   - bumpRolePermissionsGenerationTx: the seed row system_metadata.updated_at.
//
// They are appended to hostZoneWriters, so TestHookBypassTimeWriters_StoreUTCOnNonUTCHost drives
// them with TZ=Asia/Kolkata on SQLite (the stored text must be UTC and inside the window) and, with
// KEYORIX_TEST_PG_DSN, on PostgreSQL (the instant must be right).
//
// Not driven here, and why they are classified harmless (listed in the PR):
//   - models.ValidateShareUpdate stamps share.UpdatedAt, but UpdateShareRecord writes the column from
//     `existing.UpdatedAt = time.Now().UTC()` (UpdateShareRecord, above in hostZoneWriters);
//   - defaultAnomalyConfig is returned by GetAnomalyConfig and never persisted by the store
//     (TestDefaultAnomalyConfigIsNeverPersisted).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func init() {
	hostZoneWriters = append(hostZoneWriters,
		hostZoneWriter{"CreateShareRecord created_at (ValidateShareRecord stamp)", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, any) {
			return "share_records", "created_at", createShareForStampTest(ctx, w)
		}},
		hostZoneWriter{"CreateShareRecord updated_at (ValidateShareRecord stamp)", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, any) {
			return "share_records", "updated_at", createShareForStampTest(ctx, w)
		}},
		hostZoneWriter{"bumpRolePermissionsGenerationTx seed row", func(ctx context.Context, w ppWorld, _ time.Time) (string, string, any) {
			// The seed is ON CONFLICT DO NOTHING: start from an install that never bumped.
			require.NoError(w.t, w.ls.db.Where("key = ?", rolePermissionsGenerationKey).Delete(&models.SystemMetadata{}).Error)
			require.NoError(w.t, bumpRolePermissionsGenerationTx(ctx, w.ls))
			return "system_metadata", "updated_at", rolePermissionsGenerationKey
		}},
	)
}

func createShareForStampTest(ctx context.Context, w ppWorld) uint {
	secret := seedSecret(w)
	created, err := w.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, OwnerID: secret.OwnerID, RecipientID: w.user(), Permission: "read",
	})
	require.NoError(w.t, err)
	return created.ID
}

// defaultAnomalyConfig stamps UpdatedAt with the host clock, which is harmless only while the
// default is never written: GetAnomalyConfig hands it to the caller and the store saves nothing.
func TestDefaultAnomalyConfigIsNeverPersisted(t *testing.T) {
	ls, _ := newPrincipalPermStorage(t, "sqlite")
	require.NoError(t, ls.db.AutoMigrate(&models.AnomalyConfigRecord{}))

	cfg, err := ls.GetAnomalyConfig(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, cfg.ID, "no saved row: the default is returned")

	var n int64
	require.NoError(t, ls.db.Model(&models.AnomalyConfigRecord{}).Count(&n).Error)
	require.Zero(t, n, "GetAnomalyConfig must not persist the default it returns")
}
