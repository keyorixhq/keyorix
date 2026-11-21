package dynamic

import (
	"crypto/tls"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #4374 audit of the postgres and mysql admin_dsn options that weaken transport
// security. Unlike mongodb and redis, these two engines are not subject to
// dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport at all: New hands
// that flag only to MongoEngine and RedisEngine ("Postgres/MySQL are pre-existing ...
// out of this change's scope", engine.go), and neither connect path asks
// netutil.Guard.RequireTLS for anything. So there is no operator policy for an
// admin_dsn option to undo; sslmode=disable and tls=false connect in clear today
// whatever the flag says.
//
// Putting the Redis precedent (refuse what undoes the policy unless the flag is set)
// on these two engines would first need the policy itself (TLS required unless the
// flag is set), which changes every existing plaintext postgres/mysql config. That is
// a policy decision, not an audit fix; it is filed as a question (ask id
// dynamic-sql-transport-policy-4374) and these tests pin what is true today, so the
// change cannot happen unnoticed in either direction.

func TestPostgresAdminDSN_SSLModeTransportToday(t *testing.T) {
	const base = "postgres://admin:s3cret@db.example.net:5432/app?sslmode="
	for _, tc := range []struct {
		mode string
		// plaintext: the first connection attempt is without TLS.
		plaintext bool
		// verifies: every TLS attempt checks the server certificate.
		verifies bool
	}{
		{"disable", true, false},
		{"allow", true, false}, // plaintext first, TLS only if the server insists
		{"prefer", false, false},
		{"require", false, false}, // TLS, no certificate or hostname check
		{"verify-ca", false, true},
		{"verify-full", false, true},
	} {
		cfg, err := parsePostgresAdminDSN(base + tc.mode)
		require.NoError(t, err, tc.mode)
		attempts := []tlsAttempt{attemptOf(cfg.TLSConfig)}
		for _, fb := range cfg.Fallbacks {
			attempts = append(attempts, attemptOf(fb.TLSConfig))
		}
		assert.Equal(t, tc.plaintext, !attempts[0].tls, "sslmode=%s: first attempt is plaintext", tc.mode)
		verifies := true
		for _, a := range attempts {
			if !a.tls || a.skipVerify {
				verifies = false
			}
		}
		assert.Equal(t, tc.verifies, verifies, "sslmode=%s: every attempt verifies the certificate", tc.mode)
	}
}

type tlsAttempt struct{ tls, skipVerify bool }

// attemptOf reads one connection attempt's TLS settings. pgx checks the certificate
// chain itself for sslmode=verify-ca (InsecureSkipVerify with VerifyPeerCertificate
// set), so that is verification; InsecureSkipVerify alone is none.
func attemptOf(c *tls.Config) tlsAttempt {
	return tlsAttempt{tls: c != nil, skipVerify: c != nil && c.InsecureSkipVerify && c.VerifyPeerCertificate == nil}
}

func TestMySQLAdminDSN_TLSParamTransportToday(t *testing.T) {
	const base = "admin:s3cret@tcp(db.example.net:3306)/app?tls="
	for _, tc := range []struct {
		value     string
		plaintext bool // no TLS at all
		verifies  bool // TLS with certificate and hostname checks
	}{
		{"false", true, false},
		{"preferred", false, false}, // TLS if offered, certificate not checked, falls back to plaintext
		{"skip-verify", false, false},
		{"true", false, true},
	} {
		cfg, err := mysql.ParseDSN(base + tc.value)
		require.NoError(t, err, tc.value)
		assert.Equal(t, tc.plaintext, cfg.TLS == nil, "tls=%s: plaintext", tc.value)
		verifies := cfg.TLS != nil && !cfg.TLS.InsecureSkipVerify
		assert.Equal(t, tc.verifies, verifies, "tls=%s: verifies the certificate", tc.value)
	}
	// The default (no tls= at all) is plaintext too.
	cfg, err := mysql.ParseDSN("admin:s3cret@tcp(db.example.net:3306)/app")
	require.NoError(t, err)
	assert.Nil(t, cfg.TLS)
}
