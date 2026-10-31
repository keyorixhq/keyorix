// utc_writes_host_zone_test.go -- UTC-WRITES-1.
//
// On the production SQLite dialect (modernc) a time.Time is stored as text in the zone it carries,
// and the expiry queries compare that text against UTC "now" bounds. A core write that keeps the
// host zone therefore stores "+0900" text on a non-UTC host, and the row expires hours early or
// late. PostgreSQL stores an instant, so the same write is harmless there.
//
// Each test runs with time.Local set to a fixed non-UTC zone and drives one write through the real
// core code. On SQLite it reads the stored column back as text and asserts the UTC wall clock was
// stored; on PostgreSQL (skipped without KEYORIX_TEST_PG_DSN) it asserts the instant is right,
// which is the only thing a timestamptz column can show. They are the proof for the writes that
// TestEveryUnhookedExpiryWriteInCoreIsUTC used to list as known exceptions, and the probes for the
// last-used writers that bypass the model BeforeSave hooks (utc_writes_last_used_test.go).
//
// None of these tests is parallel: time.Local is process-global. A parallel test only resumes
// after every sequential test has finished, so setting and restoring it here cannot be observed.

package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// hostZoneOffset is what the fixed host zone leaves in a stored value: modernc writes a time as
// "2006-01-02 15:04:05 -0700 MST", i.e. "... +0900 JST" here and "... +0000 UTC" for UTC.
const hostZoneOffset = "+0900"

// utcWritesInstant is the fixed instant the clock reports (09:00 UTC = 18:00 in the host zone).
var utcWritesInstant = time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)

// setNonUTCHostZone makes time.Local a fixed non-UTC zone for the rest of the test, the way a
// server started on a Tokyo host sees it, and restores it on cleanup.
func setNonUTCHostZone(t *testing.T) *time.Location {
	t.Helper()
	// Named like the abbreviation a real Tokyo host formats ("JST"), not "Asia/Tokyo": the text
	// SQLite stores is "... +0900 JST".
	zone := time.FixedZone("JST", 9*60*60)
	prev := time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = prev })
	return zone
}

// hostClock is c.now as production has it: the fixed instant, expressed in the host zone.
func hostClock() func() time.Time {
	return func() time.Time { return utcWritesInstant.In(time.Local) }
}

// utcDialect is one database a write is proven on.
type utcDialect struct {
	name string
	pg   bool
}

// forEachUTCDialect runs body once on the production SQLite dialect and once on PostgreSQL.
func forEachUTCDialect(t *testing.T, body func(t *testing.T, d utcDialect)) {
	t.Helper()
	for _, d := range []utcDialect{{name: "sqlite"}, {name: "postgres", pg: true}} {
		t.Run(d.name, func(t *testing.T) { body(t, d) })
	}
}

// open returns a fresh database. SQLite gets only the tables the test names; PostgreSQL is the
// fully migrated production schema (skipped when KEYORIX_TEST_PG_DSN is unset).
func (d utcDialect) open(t *testing.T, tables ...any) *gorm.DB {
	t.Helper()
	if d.pg {
		return pgOpen(t, pgMigratedDatabaseDSN(t, pgTestDSN(t)))
	}
	db := sqlitetest.OpenWithDialector(t, "utcwrites_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(tables...))
	return db
}

// requireStored asserts what one column of one row holds. SQLite: the UTC wall clock of want, as
// text, with no host offset. PostgreSQL: the instant want.
func (d utcDialect) requireStored(t *testing.T, db *gorm.DB, table, column string, want time.Time, where string, args ...any) {
	t.Helper()
	if d.pg {
		var got *time.Time
		require.NoError(t, db.Table(table).Select(column).Where(where, args...).Scan(&got).Error)
		require.NotNil(t, got, "%s.%s is NULL (where %s)", table, column, where)
		require.True(t, got.Equal(want), "stored instant %s, want %s", got.UTC(), want.UTC())
		return
	}
	var s *string
	require.NoError(t, db.Raw("SELECT CAST("+column+" AS TEXT) FROM "+table+" WHERE "+where, args...).Scan(&s).Error)
	require.NotNil(t, s, "%s.%s is NULL (where %s)", table, column, where)
	got := *s
	require.False(t, strings.Contains(got, hostZoneOffset), "stored %q carries the host zone offset", got)
	require.True(t, strings.HasSuffix(got, " +0000 UTC"), "stored %q is not in the UTC form", got)
	wantPrefix := want.UTC().Format("2006-01-02 15:04:05")
	require.True(t, strings.HasPrefix(got, wantPrefix), "stored %q, want the UTC wall clock %q", got, wantPrefix)
}

func seedAliceUser(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", Email: "a@b.com",
		EmailFolded: "a@b.com", IsActive: true, AccountState: "active"}).Error)
}

func newSessionUTCCore(db *gorm.DB) *KeyorixCore {
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: hostClock(), passwordPolicy: DefaultPasswordPolicy(),
		sessionAccessTTL: 30 * time.Minute, sessionAbsoluteTTL: 12 * time.Hour}
}

func TestRefreshSessionStoresAbsoluteExpiryAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, &models.User{}, &models.Session{}, &models.AuditEvent{},
			&models.MFASecret{}, &models.Role{}, &models.Permission{}, &models.UserRole{}, &models.RolePermission{})
		seedAliceUser(t, db)
		c := newSessionUTCCore(db)
		ctx := context.Background()

		old, err := c.mintSession(ctx, 1, "ua", "10.0.0.1")
		require.NoError(t, err)

		// A row written by a login on this non-UTC host before the fix: the ceiling sits in the
		// table as host-zone text. RefreshSession copies it into the replacement row.
		zonedCeiling := utcWritesInstant.Add(12 * time.Hour).In(time.Local)
		require.NoError(t, db.Model(&models.Session{}).Where("id = ?", old.ID).
			UpdateColumn("absolute_expires_at", zonedCeiling).Error)
		if !d.pg {
			var seeded string
			require.NoError(t, db.Raw("SELECT CAST(absolute_expires_at AS TEXT) FROM sessions WHERE id = ?", old.ID).Scan(&seeded).Error)
			require.Contains(t, seeded, hostZoneOffset, "precondition: the seeded ceiling is host-zone text")
		}

		fresh, err := c.RefreshSession(ctx, old.SessionToken)
		require.NoError(t, err)

		d.requireStored(t, db, "sessions", "absolute_expires_at", zonedCeiling, "id = ?", fresh.ID)
	})
}

// The ceiling RefreshSession copies is written by the login mint; a login on a non-UTC host must
// not leave host-zone text in the first place.
func TestMintSessionStoresAbsoluteExpiryAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, &models.User{}, &models.Session{}, &models.AuditEvent{})
		seedAliceUser(t, db)
		c := newSessionUTCCore(db)

		s, err := c.mintSession(context.Background(), 1, "ua", "10.0.0.1")
		require.NoError(t, err)

		d.requireStored(t, db, "sessions", "absolute_expires_at", utcWritesInstant.Add(12*time.Hour), "id = ?", s.ID)
	})
}

func newSSOStateCore(db *gorm.DB) *KeyorixCore {
	oidc := &SSOProvider{
		Name: "okta", Issuer: "https://idp.test", ClientID: "client-1",
		OAuth: &oauth2.Config{
			ClientID:    "client-1",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize", TokenURL: "https://idp.test/token"},
			RedirectURL: "https://keyorix.test/auth/sso/okta/callback",
			Scopes:      []string{"openid", "email"},
		},
		CompleteURL: "https://keyorix.test/auth/sso/complete",
	}
	saml := &SSOProvider{Name: "corp", Type: "saml", SAML: &stubSAML{redirect: "https://idp.test/sso", requestID: "req-1"}}
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: hostClock(),
		ssoProviders: map[string]*SSOProvider{"okta": oidc, "corp": saml}}
}

func TestBeginSSOStoresLoginStateExpiryAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, &models.SSOLoginState{})
		c := newSSOStateCore(db)

		_, err := c.BeginSSO(context.Background(), "okta", "/")
		require.NoError(t, err)

		d.requireStored(t, db, "sso_login_states", "expires_at", utcWritesInstant.Add(ssoStateTTL), "provider = ?", "okta")
	})
}

func TestBeginSAMLStoresLoginStateExpiryAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, &models.SSOLoginState{})
		c := newSSOStateCore(db)

		_, err := c.BeginSAML(context.Background(), "corp", "/")
		require.NoError(t, err)

		d.requireStored(t, db, "sso_login_states", "expires_at", utcWritesInstant.Add(ssoStateTTL), "provider = ?", "corp")
	})
}

// CreateUser takes OneTimePasswordExpiresAt from the request as given. CreateUserWithOneTimePassword
// already hands it a UTC value; this is the contract for any other caller, so the column does not
// depend on every caller remembering.
func TestCreateUserStoresOneTimePasswordExpiryAsUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		zone := setNonUTCHostZone(t)
		db := d.open(t, &models.User{}, &models.AuditEvent{}, &models.Role{}, &models.Permission{},
			&models.UserRole{}, &models.RolePermission{})
		c := &KeyorixCore{storage: store.NewLocalStorage(db), now: hostClock(), passwordPolicy: DefaultPasswordPolicy()}

		expires := utcWritesInstant.Add(24 * time.Hour).In(zone)
		_, err := c.CreateUser(context.Background(), &CreateUserRequest{
			Username: "bob", Email: "bob@example.com", Password: "Correct-Horse-Battery-9!",
			OneTimePasswordExpiresAt: &expires,
		})
		require.NoError(t, err)

		d.requireStored(t, db, "users", "one_time_password_expires_at", expires, "username = ?", "bob")
	})
}
