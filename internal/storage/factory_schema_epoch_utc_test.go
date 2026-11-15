// factory_schema_epoch_utc_test.go — #3914 residual host-zone sites in the
// schema-epoch code: recordSchemaEpochAs stamped system_metadata.updated_at with
// a host-zone time.Now() (GORM keeps a non-zero UpdatedAt, so NowFunc's UTC never
// applied), and the two refusal messages printed a stored time in whatever zone
// the row carried. Each test re-executes the test binary with TZ set (the
// runInUTCWritesHostTZ pattern of internal/core/utc_writes_host_zone_test.go:
// time.Local is process-global, so it is never assigned here); under TZ=UTC they
// would prove nothing, so the child refuses to run in a zone with no offset.
package storage

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

const schemaEpochHostZoneEnv = "KEYORIX_SCHEMA_EPOCH_HOST_ZONE"

// schemaEpochHostZones: subtest name -> IANA zone. Both have a non-zero offset all
// year (Auckland +12/+13, Los Angeles -8/-7), on opposite sides of UTC.
var schemaEpochHostZones = map[string]string{
	"Auckland":   "Pacific/Auckland",
	"LosAngeles": "America/Los_Angeles",
}

// inSchemaEpochHostZones runs body once per host zone, each in a subprocess whose
// time.Local is that zone.
func inSchemaEpochHostZones(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	for name, zone := range schemaEpochHostZones {
		t.Run(name, func(t *testing.T) {
			if got := os.Getenv(schemaEpochHostZoneEnv); got != "" {
				if got != zone {
					t.Skipf("subprocess for %s", got)
				}
				_, off := time.Now().Zone()
				require.NotZero(t, off, "TZ=%s was not adopted as time.Local; the test would prove nothing", zone)
				body(t)
				return
			}
			top, _, _ := strings.Cut(t.Name(), "/")
			cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(top)+"$/^"+name+"$", "-test.count=1", "-test.v")
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "TZ=") && !strings.HasPrefix(kv, schemaEpochHostZoneEnv+"=") {
					cmd.Env = append(cmd.Env, kv)
				}
			}
			cmd.Env = append(cmd.Env, "TZ="+zone, schemaEpochHostZoneEnv+"="+zone)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "subprocess TZ=%s failed:\n%s", zone, out)
			require.Contains(t, string(out), "--- PASS: "+top+"/"+name+" ", "subprocess TZ=%s did not run %s/%s:\n%s", zone, top, name, out)
		})
	}
}

// TestRecordSchemaEpochAs_StampsUpdatedAtInUTC: the epoch and floor rows' updated_at
// is stored as a UTC instant, whatever the host zone.
func TestRecordSchemaEpochAs_StampsUpdatedAtInUTC(t *testing.T) {
	inSchemaEpochHostZones(t, func(t *testing.T) {
		db, err := gormOpenForTest(t, t.TempDir()+"/epoch-utc-stamp.db")
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
		require.NoError(t, recordSchemaEpochAs(db, currentSchemaEpoch, minCompatibleSchemaEpoch))

		for _, key := range []string{schemaEpochMetadataKey, schemaMinCompatibleEpochMetadataKey} {
			var text string
			require.NoError(t, db.Raw("SELECT CAST(updated_at AS TEXT) FROM system_metadata WHERE key = ?", key).Scan(&text).Error)
			var got time.Time
			require.NoError(t, db.Raw("SELECT updated_at FROM system_metadata WHERE key = ?", key).Scan(&got).Error)
			_, off := got.Zone()
			require.Zero(t, off, "%s updated_at is stored in the host zone (%q); it must be a UTC instant", key, text)
		}
	})
}

// TestCheckSchemaEpoch_RefusalNamesRecordedTimeInUTC: a row written in a non-UTC
// zone (an older binary, or a direct write) is reported as the same instant in UTC,
// for both refusals that print a recorded-at time.
func TestCheckSchemaEpoch_RefusalNamesRecordedTimeInUTC(t *testing.T) {
	inSchemaEpochHostZones(t, func(t *testing.T) {
		require.NoError(t, i18n.InitializeForTesting())
		defer i18n.ResetForTesting()

		// 2026-11-14 01:00 at +13:00 is 2026-11-13T12:00:00Z; the zone is set explicitly so
		// the stored text carries an offset whatever the driver does with time.Local.
		at := time.Date(2026, 11, 14, 1, 0, 0, 0, time.FixedZone("NZDT", 13*3600))
		wantUTC := "recorded at 2026-11-13T12:00:00Z"
		newer := strconv.Itoa(currentSchemaEpoch + 1)

		t.Run("epoch without floor", func(t *testing.T) {
			db, err := gormOpenForTest(t, t.TempDir()+"/epoch-utc-newer.db")
			require.NoError(t, err)
			require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
			require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: newer, UpdatedAt: at}).Error)
			err = checkSchemaEpoch(db)
			require.Error(t, err)
			require.Contains(t, err.Error(), wantUTC)
		})
		t.Run("floor above binary", func(t *testing.T) {
			db, err := gormOpenForTest(t, t.TempDir()+"/epoch-utc-floor.db")
			require.NoError(t, err)
			require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
			require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: newer, UpdatedAt: at}).Error)
			require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaMinCompatibleEpochMetadataKey, Value: newer, UpdatedAt: at}).Error)
			err = checkSchemaEpoch(db)
			require.Error(t, err)
			require.Contains(t, err.Error(), "floor recorded at 2026-11-13T12:00:00Z")
		})
	})
}
