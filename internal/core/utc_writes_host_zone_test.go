// utc_writes_host_zone_test.go -- UTC-WRITES-1.
//
// On the production SQLite dialect (modernc) a time.Time is stored as text in the zone it carries,
// and SQLite compares that text by wall clock. A core write that keeps the host zone therefore
// stores "+0900" text on a non-UTC host, inconsistent with every other expiry column; any SQL
// predicate over it (the last-used "only move forward" updates, the stale counts) orders it
// against UTC bounds by wall clock. The expiry columns covered here are checked in Go with
// Before/After, so for them the tests prove the stored text, not an early or late expiry.
// PostgreSQL stores an instant, so the same write is harmless there.
//
// Each test runs with time.Local set to a fixed non-UTC zone and drives one write through the real
// core code. On SQLite it reads the stored column back as text and asserts the UTC wall clock was
// stored; on PostgreSQL (skipped without KEYORIX_TEST_PG_DSN) it asserts the instant is right,
// which is the only thing a timestamptz column can show. They are the proof for the writes that
// TestEveryUnhookedExpiryWriteInCoreIsUTC used to list as known exceptions, and the probes for the
// last-used writers that bypass the model BeforeSave hooks (utc_writes_last_used_test.go).
//
// time.Local is process-global, so these tests never assign it: forEachUTCDialect re-executes the
// test binary with TZ=Asia/Tokyo and the body runs there (the runInHostTZ pattern of
// server/admin/backup_restore_tz_test.go).

package core

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

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

// utcWritesChildEnv marks a subprocess of the test binary started with TZ=utcWritesHostTZ. The host
// zone is process-global, so it is never assigned in-process (TestNoTestAssignsTimeLocal); the
// dialect subtests run in a child that the runtime itself started in that zone.
const utcWritesChildEnv = "KEYORIX_TEST_UTC_WRITES_CHILD"

// utcWritesHostTZ is a Tokyo host: +0900 all year, abbreviated "JST", which is what SQLite stores
// ("... +0900 JST").
const utcWritesHostTZ = "Asia/Tokyo"

// setNonUTCHostZone returns the host zone of the subprocess the test runs in, after checking that
// the runtime really adopted utcWritesHostTZ as time.Local.
func setNonUTCHostZone(t *testing.T) *time.Location {
	t.Helper()
	require.Equal(t, utcWritesHostTZ, os.Getenv(utcWritesChildEnv), "must run inside forEachUTCDialect's host-zone subprocess")
	name, off := utcWritesInstant.In(time.Local).Zone()
	require.Equal(t, "JST", name)
	require.Equal(t, 9*60*60, off)
	return time.Local
}

// runInUTCWritesHostTZ re-executes this test binary (same flags, so -race is kept) for the subtest
// `top/sub` with TZ=utcWritesHostTZ and requires that it ran and passed. A skip of `top/sub` itself
// in the child (no PostgreSQL DSN, see forEachUTCDialect) is a skip here. A skip of any subtest
// nested under it fails: the child would still print PASS for `top/sub`, and the parent would
// report coverage that never ran.
func runInUTCWritesHostTZ(t *testing.T, top, sub string) {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TZ=") && !strings.HasPrefix(kv, utcWritesChildEnv+"=") {
			env = append(env, kv)
		}
	}
	env = append(env, "TZ="+utcWritesHostTZ, utcWritesChildEnv+"="+utcWritesHostTZ)
	cmd := exec.Command(exe, "-test.run=^"+top+"$/^"+sub+"$", "-test.v", "-test.count=1", "-test.timeout=20m")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "subprocess TZ=%s failed:\n%s", utcWritesHostTZ, out)
	if strings.Contains(string(out), "--- SKIP: "+top+"/"+sub+" ") {
		t.Skipf("skipped in the TZ=%s subprocess", utcWritesHostTZ)
	}
	require.NotContains(t, string(out), "--- SKIP: "+top+"/"+sub+"/", "subprocess TZ=%s skipped a subtest of %s/%s, so its PASS covers nothing:\n%s", utcWritesHostTZ, top, sub, out)
	require.Contains(t, string(out), "--- PASS: "+top+"/"+sub+" ", "subprocess TZ=%s did not run %s/%s:\n%s", utcWritesHostTZ, top, sub, out)
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

// forEachUTCDialect runs body once on the production SQLite dialect and once on PostgreSQL, each in
// a subprocess whose host zone is utcWritesHostTZ. In the parent it only launches and checks the
// child; the body runs in the child. Without KEYORIX_TEST_PG_DSN the postgres subtest skips here,
// at the dialect level, before body runs, so the parent sees the skip even when body opens the
// database inside nested subtests.
func forEachUTCDialect(t *testing.T, body func(t *testing.T, d utcDialect)) {
	t.Helper()
	child := os.Getenv(utcWritesChildEnv) != ""
	for _, d := range []utcDialect{{name: "sqlite"}, {name: "postgres", pg: true}} {
		t.Run(d.name, func(t *testing.T) {
			if !child {
				runInUTCWritesHostTZ(t, strings.SplitN(t.Name(), "/", 2)[0], d.name)
				return
			}
			if d.pg && os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
				t.Skip("KEYORIX_TEST_PG_DSN not set — skipping the PostgreSQL half of this UTC-write test")
			}
			body(t, d)
		})
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
