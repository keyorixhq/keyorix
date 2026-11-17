package admin

// refuseBackupDEKBehindDatabase (#4104) on its own. Gated on KEYORIX_TEST_PG_DSN.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The decision table of refuseBackupDEKBehindDatabase on its own, and fail
// closed when system_metadata cannot be read.
func TestRefuseBackupDEKBehindDatabase_Postgres(t *testing.T) {
	const own = "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name          string
		epoch, marker string // "" = no row
		refused       string // "" = allowed
	}{
		{"epoch is this DEK", own, "", ""},
		{"completed rotation's marker beside this DEK's epoch", own, "v2", ""},
		{"fence left by a rotation that never committed", "rotating:" + own, "", ""},
		{"no epoch seeded yet", "", "", ""},
		{"committed rotation, this directory behind", "fedcba98765432100123456789abcdef", "v2", "a DEK rotation committed its re-encryption sweep"},
		{"redo marker without an epoch", "", "v2", "a DEK rotation committed its re-encryption sweep"},
		{"rotated elsewhere and finished", "fedcba98765432100123456789abcdef", "", "is not the DEK the database is encrypted under"},
		{"another rotation's fence", "rotating:fedcba98765432100123456789abcdef", "", "is not the DEK the database is encrypted under"},
	}
	db := pgAdminRawOpen(t, pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t)))
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, db.Where("1 = 1").Delete(&models.SystemMetadata{}).Error)
			if c.epoch != "" {
				require.NoError(t, db.Create(&models.SystemMetadata{Key: "dek.epoch", Value: c.epoch}).Error)
			}
			if c.marker != "" {
				require.NoError(t, db.Create(&models.SystemMetadata{Key: "dek_rotation.promote_pending", Value: c.marker}).Error)
			}
			err := refuseBackupDEKBehindDatabase(db, own)
			if c.refused == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, encryption.ErrDEKEpochMismatch)
			require.ErrorContains(t, err, c.refused)
			require.ErrorContains(t, err, "no archive was written and no key file was changed")
		})
	}

	empty := pgAdminRawOpen(t, pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))) // no system_metadata table
	err := refuseBackupDEKBehindDatabase(empty, own)
	require.ErrorContains(t, err, "could not read the database's DEK epoch")
}
