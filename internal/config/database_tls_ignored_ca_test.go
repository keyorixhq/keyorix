package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PG-SSL-ROOT-CERT-1: a CA the connection would never check the server
// against is refused, in the fields and in a dsn. pgx loads an sslrootcert
// file under allow/prefer but sets InsecureSkipVerify (and may fall back to
// plaintext); under disable there is no TLS at all. sslrootcert=system is the
// exception for allow/prefer only, because pgx upgrades it to verify-full.
func TestValidate_RootCertTheConnectionWouldIgnore_Refused(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")

	fieldCases := []struct {
		mode, rootCert string
		refused        bool
		why            string
	}{
		{"disable", ca, true, "neither encrypted nor verified"},
		{"allow", ca, true, "never checks the database server's certificate"},
		{"prefer", ca, true, "never checks the database server's certificate"},
		{"disable", SSLRootCertSystem, true, "neither encrypted nor verified"},
		{"allow", SSLRootCertSystem, false, ""}, // pgx: system -> verify-full
		{"prefer", SSLRootCertSystem, false, ""},
		{"require", ca, false, ""}, // pgx/libpq: require + CA file = verify-ca
		{"verify-ca", ca, false, ""},
		{"verify-full", ca, false, ""},
		{"prefer", "", false, ""}, // no CA named: the insecure-settings registry warns, as before
	}
	for _, tc := range fieldCases {
		t.Run("fields/"+tc.mode+"/"+tc.rootCert, func(t *testing.T) {
			err := postgresConfig(pgFields(tc.mode, tc.rootCert)).Validate()
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "storage.database.ssl_root_cert is set but storage.database.ssl_mode is "+tc.mode)
			assert.Contains(t, err.Error(), tc.why)
			assert.Contains(t, err.Error(), "refusing to start")
			assert.Contains(t, err.Error(), "set ssl_mode to verify-full")
		})
	}

	dsnCases := []struct {
		name, dsn, pgsslmode string
		refused              bool
	}{
		{"prefer+file", "host=db user=k password=hunter2 sslmode=prefer sslrootcert=" + ca, "", true},
		{"allow+file", "postgres://k:hunter2@db/k?sslmode=allow&sslrootcert=" + ca, "", true},
		{"disable+file", "host=db user=k password=hunter2 sslmode=disable sslrootcert=" + ca, "", true},
		{"disable+system", "host=db user=k password=hunter2 sslmode=disable sslrootcert=system", "", true},
		// no sslmode in the dsn: pgx's default is prefer
		{"default+file", "host=db user=k password=hunter2 sslrootcert=" + ca, "", true},
		{"PGSSLMODE prefer+file", "host=db user=k password=hunter2 sslrootcert=" + ca, "prefer", true},
		{"prefer+system", "host=db user=k sslmode=prefer sslrootcert=system", "", false},
		{"require+file", "host=db user=k sslmode=require sslrootcert=" + ca, "", false},
		{"verify-full+file", "host=db user=k sslmode=verify-full sslrootcert=" + ca, "", false},
		{"PGSSLMODE verify-full+file", "host=db user=k sslrootcert=" + ca, "verify-full", false},
	}
	for _, tc := range dsnCases {
		t.Run("dsn/"+tc.name, func(t *testing.T) {
			t.Setenv("PGSSLMODE", tc.pgsslmode)
			err := postgresConfig(&DatabaseConfig{DSN: tc.dsn}).Validate()
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "storage.database.dsn sets sslrootcert but its effective sslmode is")
			assert.Contains(t, err.Error(), "refusing to start")
			assert.Contains(t, err.Error(), "put sslmode=verify-full in the dsn")
			assert.NotContains(t, err.Error(), "hunter2", "the DSN (and its password) must never be echoed")
		})
	}
}

// Every connection goes through ResolvePostgresConnConfig, so the refusal also
// holds for entry points that never run Config.Validate (admin subcommands).
func TestResolvePostgresConnConfig_RefusesIgnoredRootCert(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")
	cc, err := ResolvePostgresConnConfig(pgFields("prefer", ca))
	require.Error(t, err)
	assert.Nil(t, cc)
	assert.Contains(t, err.Error(), "storage.database.ssl_mode is prefer")
}
