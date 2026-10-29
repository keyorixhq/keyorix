package backupfmt

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// v095NotificationChannelColumns is notification_channels' column list in a
// v0.95.3 archive's manifest (before #2468 added url_enc/url_meta).
var v095NotificationChannelColumns = []string{
	"id", "name", "type", "enabled", "url", "email", "events",
	"max_retries", "retry_backoff_ms", "created_at", "updated_at", "created_by",
}

func loadNotificationChannelArchive(t *testing.T, columns []string, ndjson string) (*gorm.DB, error) {
	t.Helper()
	const tarName = "tables/notification_channels.ndjson"
	stagingDir := t.TempDir()
	require.NoError(t, stageFile(stagingDir, tarName, []byte(ndjson)))
	rows := int64(0)
	for _, c := range ndjson {
		if c == '\n' {
			rows++
		}
	}
	manifest := Manifest{FormatVersion: FormatVersion, Backend: Backend, Tables: []TableEntry{{
		Name: "notification_channels", TarName: tarName, RowCount: rows, Columns: columns,
	}}}
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	return db, db.Transaction(func(tx *gorm.DB) error { return LoadArchive(tx, manifest, stagingDir) })
}

// TestLoadArchive_V095NotificationChannelURLIsCarried (#3452): a v0.95.x
// archive's notification_channels.url is no longer a column of the current
// model. Restore used to refuse the whole archive over it; now the value is
// written to the raw legacy column, where the startup backfill
// (MigrateNotificationChannelURLsToEncrypted) reads it.
func TestLoadArchive_V095NotificationChannelURLIsCarried(t *testing.T) {
	db, err := loadNotificationChannelArchive(t, v095NotificationChannelColumns,
		`{"ID":1,"Name":"hook","Type":"webhook","Enabled":true,"URL":"https://203.0.113.10/a","Events":"","MaxRetries":3,"RetryBackoffMs":1000,"CreatedAt":"2026-10-01T00:00:00Z","UpdatedAt":"2026-10-01T00:00:00Z","CreatedBy":"admin"}
{"ID":2,"Name":"mail","Type":"email","Enabled":true,"URL":"","Email":"ops@example.test","Events":"","MaxRetries":3,"RetryBackoffMs":1000,"CreatedAt":"2026-10-01T00:00:00Z","UpdatedAt":"2026-10-01T00:00:00Z","CreatedBy":"admin"}
`)
	require.NoError(t, err)
	var got []struct {
		ID  uint
		URL *string
	}
	require.NoError(t, db.Raw("SELECT id, url FROM notification_channels ORDER BY id").Scan(&got).Error)
	require.Len(t, got, 2)
	require.NotNil(t, got[0].URL)
	require.Equal(t, "https://203.0.113.10/a", *got[0].URL)
	require.Nil(t, got[1].URL, "an empty legacy value is not written")
}

// TestLoadArchive_NoLegacyColumnNoSchemaChange: an archive without the legacy
// column (any post-#2468 backup) leaves the target's schema alone.
func TestLoadArchive_NoLegacyColumnNoSchemaChange(t *testing.T) {
	cols := []string{"id", "name", "type", "enabled", "url_enc", "url_meta", "email", "events",
		"max_retries", "retry_backoff_ms", "created_at", "updated_at", "created_by"}
	db, err := loadNotificationChannelArchive(t, cols,
		`{"ID":1,"Name":"hook","Type":"webhook","Enabled":true,"URLEnc":"cA==","URLMeta":null,"Events":"","MaxRetries":3,"RetryBackoffMs":1000,"CreatedAt":"2026-10-01T00:00:00Z","UpdatedAt":"2026-10-01T00:00:00Z","CreatedBy":"admin"}
`)
	require.NoError(t, err)
	types, err := db.Migrator().ColumnTypes("notification_channels")
	require.NoError(t, err)
	for _, c := range types {
		require.NotEqual(t, "url", c.Name())
	}
}

// TestLoadArchive_UnknownColumnBesideLegacyStillRefused: the allowance is
// for the one named column; any other unmapped column is still refused.
func TestLoadArchive_UnknownColumnBesideLegacyStillRefused(t *testing.T) {
	_, err := loadNotificationChannelArchive(t, append(append([]string{}, v095NotificationChannelColumns...), "webhook_secret"), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), `"webhook_secret"`)
}

// TestLegacyColumns_AreUnmappedFieldsOfTheirModel keeps legacyColumns honest:
// each entry's column must NOT be a column of the current model (otherwise
// the normal load already carries it and the entry is stale), and its JSONKey
// must still be a gorm:"-" field of that model -- the field whose name old
// binaries used as the row key.
func TestLegacyColumns_AreUnmappedFieldsOfTheirModel(t *testing.T) {
	byName := modelsByTypeName()
	require.NotEmpty(t, legacyColumns)
	for _, lc := range legacyColumns {
		m, ok := byName[lc.Model]
		require.True(t, ok, "legacyColumns names unknown model %s", lc.Model)
		s, err := parseSchema(m)
		require.NoError(t, err)
		require.NotContains(t, s.DBNames, lc.Column, "%s.%s is a live column again; drop the legacyColumns entry", lc.Model, lc.Column)
		f, ok := reflect.TypeOf(m).Elem().FieldByName(lc.JSONKey)
		require.True(t, ok, "%s has no field %s", lc.Model, lc.JSONKey)
		require.Equal(t, "-", f.Tag.Get("gorm"), "%s.%s must be the unmapped legacy field", lc.Model, lc.JSONKey)
		require.NotEmpty(t, lc.Backfill)
	}
}
