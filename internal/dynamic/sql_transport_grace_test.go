package dynamic

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// plaintextFakeServer is the transport policy of tests whose fake target speaks the
// database protocol without TLS (loopback, like allowPrivateNetwork: true): those
// tests are about what the engine sends, not about transport. The policy itself is
// tested in sql_transport_policy_test.go and below.
var plaintextFakeServer = sqlTransportPolicy{allowInsecure: true}

func captureTransportLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &logs
}

// New hands the operator flag to postgres and mysql and puts them under the soft
// period of dsn.StoredSQLTransportGrace; the engines it returns tell core what
// they will do (ports.DynamicAdminDSNTransportInspector), through Contain.
func TestNew_SQLEnginesCarryTheTransportPolicy(t *testing.T) {
	for _, backend := range []string{"postgres", "mysql"} {
		for _, allow := range []bool{false, true} {
			eng, err := New(backend, true, allow)
			require.NoError(t, err)
			inner := eng.(*containedEngine).inner
			var got sqlTransportPolicy
			switch e := inner.(type) {
			case *PostgresEngine:
				got = e.transport
			case *MySQLEngine:
				got = e.transport
			}
			assert.Equal(t, sqlTransportPolicy{allowInsecure: allow, storedGrace: dsn.StoredSQLTransportGrace}, got, "%s allow=%v", backend, allow)
			_, ok := eng.(ports.DynamicAdminDSNTransportInspector)
			assert.True(t, ok, "%s: the contained engine must answer core's transport question", backend)
		}
	}
	weak := map[string]string{"postgres": pgClosed + "&sslmode=require", "mysql": mysqlClosed + "&tls=skip-verify"}
	good := map[string]string{"postgres": pgClosed + "&sslmode=verify-full", "mysql": mysqlClosed + "&tls=true"}
	for backend := range weak {
		eng, err := New(backend, true, false)
		require.NoError(t, err)
		inspector := eng.(ports.DynamicAdminDSNTransportInspector)
		assert.NotNil(t, inspector.AdminDSNTransportWeakness(weak[backend]), backend)
		assert.Nil(t, inspector.AdminDSNTransportWeakness(good[backend]), backend)
	}
	eng, err := New("mongodb", true, false)
	require.NoError(t, err)
	assert.Nil(t, eng.(ports.DynamicAdminDSNTransportInspector).AdminDSNTransportWeakness("mongodb://h/app"), "engines without the setting report nothing")
}

// During the soft period a stored weak admin_dsn still connects, with a WARNING
// that names the backend and option only.
func TestSQLEngines_SoftPeriodConnectsWithWarning(t *testing.T) {
	isolatePGEnv(t)
	grace := sqlTransportPolicy{storedGrace: true}
	for _, tc := range []struct {
		name string
		run  func() error
		want string
	}{
		{"postgres issue", func() error {
			_, _, err := (&PostgresEngine{allowPrivateNetwork: true, transport: grace}).Issue(context.Background(), pgClosed+"&sslmode=require", "", time.Minute)
			return err
		}, "WARNING: postgres admin_dsn has sslmode=require"},
		{"postgres revoke", func() error {
			return (&PostgresEngine{allowPrivateNetwork: true, transport: grace}).Revoke(context.Background(), pgClosed+"&sslmode=prefer", "kx_dyn_test")
		}, "WARNING: postgres admin_dsn has sslmode=prefer"},
		{"mysql issue", func() error {
			_, _, err := (&MySQLEngine{allowPrivateNetwork: true, transport: grace}).Issue(context.Background(), mysqlClosed+"&tls=skip-verify", "", time.Minute)
			return err
		}, "WARNING: mysql admin_dsn has tls=skip-verify"},
		{"mysql revoke", func() error {
			return (&MySQLEngine{allowPrivateNetwork: true, transport: grace}).Revoke(context.Background(), mysqlClosed, "kx_dyn_test")
		}, "WARNING: mysql admin_dsn has tls=false"},
	} {
		logs := captureTransportLog(t)
		err := tc.run()
		require.Error(t, err, tc.name) // nothing listens
		_, refused := errors.AsType[*dsn.ForbiddenOptionError](err)
		assert.False(t, refused, "%s: %v", tc.name, err)
		assert.NotContains(t, err.Error(), "revoke ran without", "%s: the soft period revokes as it issues", tc.name)
		assert.Contains(t, logs.String(), tc.want, tc.name)
		assert.Contains(t, logs.String(), "grace period", tc.name)
		assert.NotContains(t, logs.String(), "s3cret", tc.name)
		assert.NotContains(t, logs.String(), "127.0.0.1", "%s: the WARNING names the option, not the DSN", tc.name)
	}
}

// With the operator's flag a weak admin_dsn connects, logged as explicitly enabled.
func TestSQLEngines_OperatorFlagConnectsWithWarning(t *testing.T) {
	isolatePGEnv(t)
	logs := captureTransportLog(t)
	_, _, err := (&PostgresEngine{allowPrivateNetwork: true, transport: plaintextFakeServer}).Issue(context.Background(), pgClosed+"&sslmode=disable", "", time.Minute)
	requireNotTransportRefusal(t, err, "postgres disable with the flag")
	_, _, err = (&MySQLEngine{allowPrivateNetwork: true, transport: plaintextFakeServer}).Issue(context.Background(), mysqlClosed+"&tls=preferred", "", time.Minute)
	requireNotTransportRefusal(t, err, "mysql preferred with the flag")
	assert.Contains(t, logs.String(), "WARNING: postgres admin_dsn has sslmode=disable")
	assert.Contains(t, logs.String(), "WARNING: mysql admin_dsn has tls=preferred")
	assert.Equal(t, 2, strings.Count(logs.String(), "explicitly enabled"), logs.String())
	assert.NotContains(t, logs.String(), "s3cret")
}

// The revoke upgrade leaves no attempt that skips verification or is plaintext.
func TestRevokeUpgrade_LeavesOnlyVerifiedAttempts(t *testing.T) {
	isolatePGEnv(t)
	for _, mode := range []string{"disable", "allow", "prefer", "require"} {
		cfg, err := parsePostgresAdminDSN("postgres://admin:s3cret@db1.example.net:5432,db2.example.net:5433/app?sslmode=" + mode)
		require.NoError(t, err)
		upgradePostgresToVerifyFull(&cfg.Config)
		assert.Nil(t, postgresTransportWeakness(&cfg.Config), mode)
		assert.Len(t, cfg.Fallbacks, 1, "%s: one attempt per host", mode)
		assert.Equal(t, "db1.example.net", cfg.TLSConfig.ServerName, mode)
		assert.Equal(t, "db2.example.net", cfg.Fallbacks[0].TLSConfig.ServerName, mode)
	}
	for _, v := range []string{"false", "skip-verify", "preferred", "true&allowFallbackToPlaintext=true"} {
		cfg, err := mysql.ParseDSN("admin:s3cret@tcp(db.example.net:3306)/app?tls=" + v)
		require.NoError(t, err)
		upgradeMySQLToVerified(cfg)
		assert.Nil(t, mysqlTransportWeakness(cfg), v)
		assert.Equal(t, "db.example.net", cfg.TLS.ServerName, v)
	}
}

//go:embed testdata/taint-keys.txt
var transportVocabularyRaw string

// transportValues are the spellings the drivers give a meaning to; the mined
// vocabulary (identifier-like literals of pgx, mongo-driver and go-sql-driver)
// does not hold the hyphenated ones.
var transportValues = []string{
	"disable", "allow", "prefer", "require", "verify-ca", "verify-full",
	"true", "false", "skip-verify", "preferred", "TRUE", "SKIP-VERIFY", "1", "0", "",
}

// Class guard: whatever an admin_dsn spells (every word of the mined driver
// vocabulary as an extra option, and as the value of sslmode, tls and
// allowFallbackToPlaintext), either the parsed config verifies the server
// certificate on every attempt, or the engine refuses it. Read from the config
// pgx / go-sql-driver build, not from the DSN text.
func TestSQLTransport_NoSpellingConnectsUnverifiedUnrefused(t *testing.T) {
	isolatePGEnv(t)
	words := append(strings.Fields(transportVocabularyRaw), transportValues...)
	var pgDSNs, myDSNs []string
	for _, w := range words {
		pgDSNs = append(pgDSNs,
			"postgres://admin:s3cret@db.example.net/app?sslmode="+w,
			"postgres://admin:s3cret@db.example.net/app?sslmode=verify-full&"+w+"=disable",
			"host=db.example.net user=admin password=s3cret sslmode=verify-full "+w+"=require")
		myDSNs = append(myDSNs,
			"admin:s3cret@tcp(db.example.net:3306)/app?tls="+w,
			"admin:s3cret@tcp(db.example.net:3306)/app?tls=true&"+w+"=true",
			"admin:s3cret@tcp(db.example.net:3306)/app?tls=true&"+w+"=skip-verify",
			"admin:s3cret@tcp(db.example.net:3306)/app?tls=true&allowFallbackToPlaintext="+w)
	}
	// The oracle is written out here, not taken from postgresVerifies, so a change
	// to the production helper shows up as a disagreement.
	pgAttemptVerifies := func(c *tls.Config) bool {
		return c != nil && (!c.InsecureSkipVerify || c.VerifyPeerCertificate != nil)
	}
	pg := &PostgresEngine{}
	checked := 0
	for _, d := range pgDSNs {
		cfg, err := parsePostgresAdminDSN(d)
		if err != nil {
			continue // Issue refuses it before any dial
		}
		checked++
		verifies := pgAttemptVerifies(cfg.TLSConfig)
		for _, fb := range cfg.Fallbacks {
			verifies = verifies && pgAttemptVerifies(fb.TLSConfig)
		}
		if refused := pg.AdminDSNTransportWeakness(d) != nil; refused == verifies {
			t.Errorf("%q: verifies=%v but refused=%v", d, verifies, refused)
		}
	}
	// Through Contain, as core calls it: go-sql-driver panics on some parameters
	// (strict=true), and a panic must answer "refuse", not crash or pass.
	my := Contain(&MySQLEngine{}).(ports.DynamicAdminDSNTransportInspector)
	for _, d := range myDSNs {
		cfg, panicked, err := parseMySQLRecovering(d)
		if panicked {
			assert.NotNil(t, my.AdminDSNTransportWeakness(d), "%q: the driver panics on it, so it must be refused", d)
			continue
		}
		if err != nil {
			continue
		}
		checked++
		verifies := cfg.TLS != nil && !cfg.TLS.InsecureSkipVerify && !cfg.AllowFallbackToPlaintext
		if refused := my.AdminDSNTransportWeakness(d) != nil; refused == verifies {
			t.Errorf("%q: verifies=%v but refused=%v", d, verifies, refused)
		}
	}
	// The guard must have looked at both sides.
	require.Greater(t, checked, len(words), "too few DSNs parsed for the guard to mean anything")
	assert.NotNil(t, pg.AdminDSNTransportWeakness("postgres://admin:s3cret@db.example.net/app?sslmode=require"))
	assert.Nil(t, pg.AdminDSNTransportWeakness("postgres://admin:s3cret@db.example.net/app?sslmode=verify-full"))
}

func parseMySQLRecovering(d string) (cfg *mysql.Config, panicked bool, err error) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	cfg, err = mysql.ParseDSN(d)
	return cfg, false, err
}
