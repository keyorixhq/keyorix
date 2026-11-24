package dynamic

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// #4374: the operator's transport policy (dynamic_secrets.insecure_allow_plaintext_
// dynamic_secret_transport) covers postgres and mysql admin_dsns. Without the flag
// only a connection that verifies the server certificate is accepted: sslmode
// verify-ca/verify-full for postgres, tls=true for mysql. The decision reads the
// parsed driver config, so every spelling that reaches the same config is caught.
//
// These tests use only what main already had (an engine value, Issue, Revoke,
// dsn.ForbiddenOptionError), so they are the red/green proof: on main nothing is
// refused and Revoke names no dropped option. An engine built as a literal has
// the zero transport policy, which is the next release's hard refusal (no flag, no
// soft period); the soft period and the flag are in sql_transport_grace_test.go.
// Nothing listens on 127.0.0.1:1, so a DSN the policy accepts fails to connect.

const pgClosed = "postgres://admin:s3cret@127.0.0.1:1/app?connect_timeout=1"

func requireTransportRefusal(t *testing.T, err error, backend, option, what string) {
	t.Helper()
	fe, ok := errors.AsType[*dsn.ForbiddenOptionError](err)
	require.True(t, ok, "%s: want a transport refusal, got %v", what, err)
	assert.Equal(t, backend, fe.Backend, what)
	assert.Equal(t, option, fe.Option, what)
	assert.Contains(t, err.Error(), "insecure_allow_plaintext_dynamic_secret_transport", what)
	assert.NotContains(t, err.Error(), "s3cret", "%s: the error must not quote the DSN", what)
}

func requireNotTransportRefusal(t *testing.T, err error, what string) {
	t.Helper()
	require.Error(t, err, what) // nothing listens
	_, refused := errors.AsType[*dsn.ForbiddenOptionError](err)
	assert.False(t, refused, "%s: a verifying admin_dsn must not be refused: %v", what, err)
}

func TestPostgresEngine_RefusesSSLModesThatDoNotVerify(t *testing.T) {
	isolatePGEnv(t)
	for _, tc := range []struct{ name, dsn, option string }{
		{"disable", pgClosed + "&sslmode=disable", "sslmode=disable"},
		{"allow", pgClosed + "&sslmode=allow", "sslmode=allow"},
		{"prefer", pgClosed + "&sslmode=prefer", "sslmode=prefer"},
		{"require", pgClosed + "&sslmode=require", "sslmode=require"},
		{"sslmode not set (pgx default prefer)", pgClosed, "sslmode=prefer"},
		{"keyword form", "host=127.0.0.1 port=1 user=admin password=s3cret dbname=app connect_timeout=1 sslmode=require", "sslmode=require"},
		{"keyword form after vertical tab", "host=127.0.0.1 port=1 user=admin password=s3cret dbname=app\vsslmode=disable", "sslmode=disable"},
		{"last value wins", pgClosed + "&sslmode=verify-full&sslmode=disable", "sslmode=disable"},
		{"multi-host", "postgres://admin:s3cret@127.0.0.1:1,127.0.0.2:1/app?connect_timeout=1&sslmode=require", "sslmode=require"},
	} {
		e := &PostgresEngine{allowPrivateNetwork: true}
		_, _, err := e.Issue(context.Background(), tc.dsn, "", time.Minute)
		requireTransportRefusal(t, err, "postgres", tc.option, tc.name)
		requireTransportRefusal(t, e.Renew(context.Background(), tc.dsn, "kx_dyn_test", time.Now()), "postgres", tc.option, tc.name+" (renew)")
	}
}

// PGSSLMODE fills sslmode when the DSN has none; the parsed config carries it.
func TestPostgresEngine_RefusesPGSSLModeEnvironmentThatDoesNotVerify(t *testing.T) {
	isolatePGEnv(t)
	t.Setenv("PGSSLMODE", "disable")
	e := &PostgresEngine{allowPrivateNetwork: true}
	_, _, err := e.Issue(context.Background(), pgClosed, "", time.Minute)
	requireTransportRefusal(t, err, "postgres", "sslmode=disable", "PGSSLMODE=disable")

	t.Setenv("PGSSLMODE", "verify-full")
	_, _, err = e.Issue(context.Background(), pgClosed, "", time.Minute)
	requireNotTransportRefusal(t, err, "PGSSLMODE=verify-full")
}

func TestPostgresEngine_VerifyingSSLModesAreNotRefused(t *testing.T) {
	isolatePGEnv(t)
	for _, mode := range []string{"verify-ca", "verify-full"} {
		e := &PostgresEngine{allowPrivateNetwork: true}
		_, _, err := e.Issue(context.Background(), pgClosed+"&sslmode="+mode, "", time.Minute)
		requireNotTransportRefusal(t, err, mode)
	}
}

const mysqlClosed = "admin:s3cret@tcp(127.0.0.1:1)/app?timeout=1s"

func TestMySQLEngine_RefusesTLSSettingsThatDoNotVerify(t *testing.T) {
	for _, tc := range []struct{ name, dsn, option string }{
		{"tls=false", mysqlClosed + "&tls=false", "tls=false"},
		{"tls=0", mysqlClosed + "&tls=0", "tls=false"},
		{"tls not set (driver default plaintext)", mysqlClosed, "tls=false"},
		{"TLS is not the tls parameter", mysqlClosed + "&TLS=true", "tls=false"},
		{"skip-verify", mysqlClosed + "&tls=skip-verify", "tls=skip-verify"},
		{"SKIP-VERIFY", mysqlClosed + "&tls=SKIP-VERIFY", "tls=skip-verify"},
		{"preferred", mysqlClosed + "&tls=preferred", "tls=preferred"},
		{"tls=true with plaintext fallback", mysqlClosed + "&tls=true&allowFallbackToPlaintext=true", "allowFallbackToPlaintext=true"},
		{"last value wins", mysqlClosed + "&tls=true&tls=skip-verify", "tls=skip-verify"},
	} {
		e := &MySQLEngine{allowPrivateNetwork: true}
		_, _, err := e.Issue(context.Background(), tc.dsn, "", time.Minute)
		requireTransportRefusal(t, err, "mysql", tc.option, tc.name)
	}
}

func TestMySQLEngine_VerifyingTLSIsNotRefused(t *testing.T) {
	for _, v := range []string{"true", "1", "TRUE"} {
		e := &MySQLEngine{allowPrivateNetwork: true}
		_, _, err := e.Issue(context.Background(), mysqlClosed+"&tls="+v, "", time.Minute)
		requireNotTransportRefusal(t, err, "tls="+v)
	}
}

// Revoke does not refuse (a refused revoke leaves the account live, #3980): it
// drops the setting, connects with the certificate verified, and says so when the
// connection then fails.
func TestPostgresEngine_Revoke_UnverifiedSSLModeUpgradedNotRefused(t *testing.T) {
	isolatePGEnv(t)
	for _, mode := range []string{"disable", "allow", "prefer", "require"} {
		e := &PostgresEngine{allowPrivateNetwork: true}
		err := e.Revoke(context.Background(), pgClosed+"&sslmode="+mode, "kx_dyn_test")
		require.Error(t, err, mode) // nothing listens
		_, refused := errors.AsType[*dsn.ForbiddenOptionError](err)
		assert.False(t, refused, "%s: revoke must not refuse: %v", mode, err)
		assert.Contains(t, err.Error(), "revoke ran without admin_dsn option sslmode="+mode, mode)
		assert.Contains(t, err.Error(), "server certificate verified", mode)
		assert.NotContains(t, err.Error(), "s3cret", mode)
	}
}

func TestMySQLEngine_Revoke_UnverifiedTLSUpgradedNotRefused(t *testing.T) {
	for _, v := range []string{"false", "skip-verify", "preferred"} {
		e := &MySQLEngine{allowPrivateNetwork: true}
		err := e.Revoke(context.Background(), mysqlClosed+"&tls="+v, "kx_dyn_test")
		require.Error(t, err, v) // nothing listens
		_, refused := errors.AsType[*dsn.ForbiddenOptionError](err)
		assert.False(t, refused, "tls=%s: revoke must not refuse: %v", v, err)
		assert.True(t, strings.Contains(err.Error(), "revoke ran without admin_dsn option tls="+v), "tls=%s: %v", v, err)
		assert.NotContains(t, err.Error(), "s3cret", v)
	}
}
