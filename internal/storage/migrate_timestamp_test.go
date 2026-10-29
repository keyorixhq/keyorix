package storage

// migrate_timestamp_test.go -- #3440: the timestamp columns migrateDatabase adds
// with a hand-written ALTER must come back through the model on SQLite.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// timestampAlterCase is one column migrateDatabase adds with a hand-written
// ALTER TABLE ... ADD COLUMN whose model field is a timestamp.
type timestampAlterCase struct {
	table, column string
	model         func() any // pointer to a zero model of table
	field         string     // the model field mapped to column
}

var timestampAlterCases = []timestampAlterCase{
	{"users", "last_login_at", func() any { return &models.User{} }, "LastLoginAt"},
	{"users", "password_changed_at", func() any { return &models.User{} }, "PasswordChangedAt"},
	{"users", "last_failed_login_at", func() any { return &models.User{} }, "LastFailedLoginAt"},
	{"users", "login_locked_until", func() any { return &models.User{} }, "LoginLockedUntil"},
	{"sessions", "last_seen_at", func() any { return &models.Session{} }, "LastSeenAt"},
	{"sessions", "absolute_expires_at", func() any { return &models.Session{} }, "AbsoluteExpiresAt"},
	{"sessions", "impersonation_started_at", func() any { return &models.Session{} }, "ImpersonationStartedAt"},
	{"secret_nodes", "last_rotated_at", func() any { return &models.SecretNode{} }, "LastRotatedAt"},
	{"secret_nodes", "deleted_at", func() any { return &models.SecretNode{} }, "DeletedAt"},
	{"secret_nodes", "cert_not_after", func() any { return &models.SecretNode{} }, "CertNotAfter"},
	{"secret_nodes", "purge_at", func() any { return &models.SecretNode{} }, "PurgeAt"},
	{"machine_identities", "cascade_suspended_at", func() any { return &models.MachineIdentity{} }, "CascadeSuspendedAt"},
}

// seedTimestampAlterRow inserts one row of table on a freshly migrated database
// and returns its id.
func seedTimestampAlterRow(t *testing.T, db *gorm.DB, table string) uint {
	t.Helper()
	switch table {
	case "users":
		u := &models.User{Username: "ts-user", Email: "ts-user@example.invalid"}
		require.NoError(t, db.Create(u).Error)
		return u.ID
	case "sessions":
		s := &models.Session{UserID: 1, SessionToken: "ts-session"}
		require.NoError(t, db.Create(s).Error)
		return s.ID
	case "secret_nodes":
		require.NoError(t, db.Exec(`INSERT INTO projects (id, name, created_at, updated_at) VALUES (1, 'p', datetime('now'), datetime('now'))`).Error)
		require.NoError(t, db.Exec(`INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (1, 1, 'e', datetime('now'), datetime('now'))`).Error)
		n := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "ts-secret", Type: "static"}
		require.NoError(t, db.Create(n).Error)
		return n.ID
	case "machine_identities":
		m := &models.MachineIdentity{Name: "ts-machine"}
		require.NoError(t, db.Create(m).Error)
		return m.ID
	}
	t.Fatalf("no seed for table %s", table)
	return 0
}

// dropColumnForUpgrade removes column from table as an install that predates it
// would lack it: every index and trigger naming it goes first (SQLite refuses
// DROP COLUMN otherwise); migrateDatabase recreates them.
func dropColumnForUpgrade(t *testing.T, db *gorm.DB, table, column string) {
	t.Helper()
	var objs []struct{ Type, Name string }
	require.NoError(t, db.Raw(`SELECT type, name FROM sqlite_master WHERE type IN ('index', 'trigger') AND sql LIKE ?`,
		"%"+column+"%").Scan(&objs).Error)
	for _, o := range objs {
		require.NoError(t, db.Exec("DROP "+strings.ToUpper(o.Type)+" "+o.Name).Error)
	}
	require.NoError(t, db.Exec("ALTER TABLE "+table+" DROP COLUMN "+column).Error)
	require.False(t, columnExists(db, table, column))
}

// timestampField reads the time a *time.Time or gorm.DeletedAt field holds.
func timestampField(t *testing.T, m any, field string) *time.Time {
	t.Helper()
	v := reflect.ValueOf(m).Elem().FieldByName(field)
	require.True(t, v.IsValid(), "model %T has no field %s", m, field)
	switch x := v.Interface().(type) {
	case *time.Time:
		return x
	case gorm.DeletedAt:
		if !x.Valid {
			return nil
		}
		return &x.Time
	}
	t.Fatalf("field %T.%s is %s, not a timestamp", m, field, v.Type())
	return nil
}

// TestTimestampAlters_SQLite_ReadBackThroughModel: for each column, a database
// that lacks it is upgraded by migrateDatabase (the hand-written ALTER is what
// adds it), a non-NULL value is written and read back through the model. A
// column the ALTER declares as "TIMESTAMP WITH TIME ZONE" fails the read: the
// SQLite driver returns the value as a string that does not scan into
// *time.Time (#3440).
func TestTimestampAlters_SQLite_ReadBackThroughModel(t *testing.T) {
	for _, c := range timestampAlterCases {
		t.Run(c.table+"."+c.column, func(t *testing.T) {
			db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "ts-alter.db"))
			require.NoError(t, err)
			f := &DefaultStorageFactory{}
			require.NoError(t, f.migrateDatabase(db))
			id := seedTimestampAlterRow(t, db, c.table)

			dropColumnForUpgrade(t, db, c.table, c.column)
			require.NoError(t, f.migrateDatabase(db))
			require.True(t, columnExists(db, c.table, c.column), "migrateDatabase must add %s.%s back", c.table, c.column)

			want := time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC)
			require.NoError(t, db.Unscoped().Model(c.model()).Where("id = ?", id).UpdateColumn(c.column, want).Error)

			got := c.model()
			require.NoError(t, db.Unscoped().First(got, id).Error, "reading %s back through the model", c.table)
			ts := timestampField(t, got, c.field)
			require.NotNil(t, ts, "%s.%s read back as NULL", c.table, c.column)
			require.True(t, ts.Equal(want), "%s.%s: got %v, want %v", c.table, c.column, ts, want)
		})
	}
}

// TestRebuildRolePKSQLite_ExpiresAtReadsBackThroughModel: the user_roles /
// group_roles primary-key rebuild recreates expires_at; a time-bound grant must
// still read back through the model afterwards.
func TestRebuildRolePKSQLite_ExpiresAtReadsBackThroughModel(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "ts-role-rebuild.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id    INTEGER NOT NULL,
		role_id    INTEGER NOT NULL,
		project_id INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME,
		PRIMARY KEY (user_id, role_id)
	)`).Error)
	require.NoError(t, rebuildRolePKSQLite(db, "user_roles", "user_id", "user_id, role_id, project_id, environment_id"))

	want := time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 5, ExpiresAt: &want}).Error)
	var got models.UserRole
	require.NoError(t, db.Where("user_id = ? AND role_id = ?", 1, 5).First(&got).Error)
	require.NotNil(t, got.ExpiresAt)
	require.True(t, got.ExpiresAt.Equal(want), "got %v, want %v", got.ExpiresAt, want)
}

// unscannableSQLiteTimestampType reports whether a SQLite declared column type
// is one the driver does not turn back into a time.Time.
func unscannableSQLiteTimestampType(declared string) bool {
	d := strings.ToLower(declared)
	return strings.Contains(d, "time zone") || d == "timestamptz"
}

// TestTimestampAlters_SupportedUpgradeSources_NoUnscannableColumn pins the
// reachability claim in sqlTimestampType's comment: a SQLite database from each
// supported upgrade source (docs/UPGRADING.md: v0.93.x and later; the real
// v093/v094/v095 fixtures FuzzUpgradeMigration uses), upgraded by this binary,
// has no column declared with a type the driver cannot scan into time.Time.
// It would fail if one of those databases already carried such a column, or if
// an upgrade step introduced one.
func TestTimestampAlters_SupportedUpgradeSources_NoUnscannableColumn(t *testing.T) {
	for _, v := range []string{"v093", "v094", "v095"} {
		t.Run(v, func(t *testing.T) {
			src := filepath.Join(repoRootU1(), "internal", "core", "testdata", "upgrade-fixtures", v, "fixture.db")
			_, err := os.Stat(src)
			require.NoError(t, err, "the %s upgrade fixture is the evidence for #3440's reachability claim", v)
			dbPath := filepath.Join(t.TempDir(), v+".db")
			copyFileU1(t, src, dbPath)
			db, err := gormOpenForTest(t, dbPath)
			require.NoError(t, err)

			check := func(stage string) {
				var cols []struct{ Tbl, Col, Typ string }
				require.NoError(t, db.Raw(`SELECT m.name AS tbl, p.name AS col, p.type AS typ
					FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type = 'table'`).Scan(&cols).Error)
				require.NotEmpty(t, cols)
				for _, c := range cols {
					require.False(t, unscannableSQLiteTimestampType(c.Typ),
						"%s %s: %s.%s is declared %q, which the SQLite driver returns as a string (#3440)", v, stage, c.Tbl, c.Col, c.Typ)
				}
			}
			check("as shipped")
			for _, c := range timestampAlterCases {
				if c.column == "purge_at" || c.column == "cascade_suspended_at" {
					continue // added after v0.95; the ALTER does run on these fixtures
				}
				require.True(t, columnExists(db, c.table, c.column),
					"%s already lacks %s.%s, so its hand-written ALTER is reachable from a supported source", v, c.table, c.column)
			}
			require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
			check("after upgrade")
		})
	}
}
