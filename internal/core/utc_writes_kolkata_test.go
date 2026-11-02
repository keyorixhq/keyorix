// utc_writes_kolkata_test.go -- AUTH-ENDPOINT-OUTAGE-1 item 4.
//
// The hook-bypassing time writers earlier sessions flagged, each driven once through the real
// core caller on a TZ=Asia/Kolkata host (+0530, a half-hour offset; UTC-WRITES-1's harness uses
// Tokyo) and read back from the production SQLite dialect as text. One subtest per site:
//
//	auth.go RefreshSession          sessions.absolute_expires_at, sessions.last_seen_at
//	sso.go BeginSSO / BeginSAML     sso_login_states.expires_at
//	users.go buildUserForCreate     users.one_time_password_expires_at
//	local_users.go UpdateLastLogin  users.last_login_at (via RecordLogin)
//	local_mfa.go recovery used_at   mfa_recovery_codes.used_at (via consumeRecoveryCodeRecovering)
//
// PostgreSQL stores an instant (timestamptz), so it is not driven here; UTC-WRITES-1's tests cover
// its half for the core sites. time.Local is never assigned: the test re-executes its own binary
// with TZ=Asia/Kolkata and the subtests run in that child.

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
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

const (
	kolkataTZ       = "Asia/Kolkata"
	kolkataChildEnv = "KEYORIX_TEST_KOLKATA_WRITES_CHILD"
)

// requireStoredUTCText asserts the SQLite text of one column is the UTC wall clock of want.
func requireStoredUTCText(t *testing.T, db *gorm.DB, table, column string, want time.Time, where string, args ...any) {
	t.Helper()
	var s *string
	require.NoError(t, db.Raw("SELECT CAST("+column+" AS TEXT) FROM "+table+" WHERE "+where, args...).Scan(&s).Error)
	require.NotNil(t, s, "%s.%s is NULL", table, column)
	require.NotContains(t, *s, "+0530", "%s.%s stored with the host offset: %q (want UTC)", table, column, *s)
	require.True(t, strings.HasSuffix(*s, " +0000 UTC"), "%s.%s stored %q, not the UTC form", table, column, *s)
	require.True(t, strings.HasPrefix(*s, want.UTC().Format("2006-01-02 15:04:05")), "%s.%s stored %q, want the UTC wall clock of %s", table, column, *s, want.UTC())
}

func TestHookBypassTimeWriters_KolkataHostStoresUTC(t *testing.T) {
	sites := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"RefreshSession", func(t *testing.T) {
			db := kolkataDB(t, &models.User{}, &models.Session{}, &models.AuditEvent{},
				&models.MFASecret{}, &models.Role{}, &models.Permission{}, &models.UserRole{}, &models.RolePermission{})
			seedAliceUser(t, db)
			c := newSessionUTCCore(db)
			old, err := c.mintSession(context.Background(), 1, "ua", "10.0.0.1")
			require.NoError(t, err)
			fresh, err := c.RefreshSession(context.Background(), old.SessionToken)
			require.NoError(t, err)
			requireStoredUTCText(t, db, "sessions", "absolute_expires_at", utcWritesInstant.Add(12*time.Hour), "id = ?", fresh.ID)
			requireStoredUTCText(t, db, "sessions", "last_seen_at", utcWritesInstant, "id = ?", fresh.ID)
		}},
		{"BeginSSO", func(t *testing.T) {
			db := kolkataDB(t, &models.SSOLoginState{})
			_, err := newSSOStateCore(db).BeginSSO(context.Background(), "okta", "/")
			require.NoError(t, err)
			requireStoredUTCText(t, db, "sso_login_states", "expires_at", utcWritesInstant.Add(ssoStateTTL), "provider = ?", "okta")
		}},
		{"BeginSAML", func(t *testing.T) {
			db := kolkataDB(t, &models.SSOLoginState{})
			_, err := newSSOStateCore(db).BeginSAML(context.Background(), "corp", "/")
			require.NoError(t, err)
			requireStoredUTCText(t, db, "sso_login_states", "expires_at", utcWritesInstant.Add(ssoStateTTL), "provider = ?", "corp")
		}},
		{"buildUserForCreate", func(t *testing.T) {
			db := kolkataDB(t, &models.User{}, &models.AuditEvent{}, &models.Role{}, &models.Permission{},
				&models.UserRole{}, &models.RolePermission{})
			c := &KeyorixCore{storage: store.NewLocalStorage(db), now: hostClock(), passwordPolicy: DefaultPasswordPolicy()}
			expires := utcWritesInstant.Add(24 * time.Hour).In(time.Local)
			_, err := c.CreateUser(context.Background(), &CreateUserRequest{
				Username: "bob", Email: "bob@example.com", Password: "Correct-Horse-Battery-9!",
				OneTimePasswordExpiresAt: &expires,
			})
			require.NoError(t, err)
			requireStoredUTCText(t, db, "users", "one_time_password_expires_at", expires, "username = ?", "bob")
		}},
		{"UpdateLastLogin", func(t *testing.T) {
			db := kolkataDB(t, &models.User{})
			seedAliceUser(t, db)
			c := &KeyorixCore{storage: store.NewLocalStorage(db), now: hostClock()}
			require.NoError(t, c.RecordLogin(context.Background(), 1))
			requireStoredUTCText(t, db, "users", "last_login_at", utcWritesInstant, "id = ?", 1)
		}},
		{"ConsumeMFARecoveryCode", func(t *testing.T) {
			db := kolkataDB(t, &models.MFARecoveryCode{})
			const code = "abcd-efgh-ijkl"
			require.NoError(t, db.Create(&models.MFARecoveryCode{UserID: 1, CodeHash: sha256Hex(normalizeRecoveryCode(code))}).Error)
			c := &KeyorixCore{storage: store.NewLocalStorage(db), now: hostClock()}
			consumed, err := c.consumeRecoveryCodeRecovering(context.Background(), 1, code)
			require.NoError(t, err)
			require.True(t, consumed)
			requireStoredUTCText(t, db, "mfa_recovery_codes", "used_at", utcWritesInstant, "user_id = ?", 1)
		}},
	}

	if os.Getenv(kolkataChildEnv) == "" {
		exe, err := os.Executable()
		require.NoError(t, err)
		env := make([]string, 0, len(os.Environ())+2)
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "TZ=") && !strings.HasPrefix(kv, kolkataChildEnv+"=") {
				env = append(env, kv)
			}
		}
		env = append(env, "TZ="+kolkataTZ, kolkataChildEnv+"=1")
		cmd := exec.Command(exe, "-test.run=^TestHookBypassTimeWriters_KolkataHostStoresUTC$", "-test.v", "-test.count=1")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		for _, s := range sites {
			t.Run(s.name, func(t *testing.T) {
				require.Contains(t, string(out), "--- PASS: TestHookBypassTimeWriters_KolkataHostStoresUTC/"+s.name+" ",
					"TZ=%s child did not pass %s:\n%s", kolkataTZ, s.name, out)
			})
		}
		require.NoError(t, err, "TZ=%s child failed:\n%s", kolkataTZ, out)
		return
	}

	name, off := utcWritesInstant.In(time.Local).Zone()
	require.Equal(t, "IST", name, "the child must run with time.Local = %s", kolkataTZ)
	require.Equal(t, 5*60*60+30*60, off)
	for _, s := range sites {
		t.Run(s.name, s.run)
	}
}

func kolkataDB(t *testing.T, tables ...any) *gorm.DB {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "kolkatawrites_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(tables...))
	return db
}
