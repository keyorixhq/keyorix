package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseTLSFilesOf(t *testing.T) {
	cases := []struct {
		name string
		d    DatabaseConfig
		want DatabaseTLSFiles
	}{
		{"fields", DatabaseConfig{SSLMode: "verify-full", SSLRootCert: "/pg/ca.pem"},
			DatabaseTLSFiles{SSLMode: "verify-full", RootCert: "/pg/ca.pem"}},
		{"keyword dsn", DatabaseConfig{DSN: "host=db sslmode=verify-ca sslrootcert=/pg/ca.pem sslcert=/pg/c.crt sslkey='/pg/c k.key'"},
			DatabaseTLSFiles{SSLMode: "verify-ca", RootCert: "/pg/ca.pem", ClientCert: "/pg/c.crt", ClientKey: "/pg/c k.key"}},
		{"url dsn", DatabaseConfig{DSN: "postgres://k@db/k?sslmode=verify-full&sslrootcert=%2Fpg%2Fca.pem&sslcert=%2Fpg%2Fc.crt&sslkey=%2Fpg%2Fc.key"},
			DatabaseTLSFiles{SSLMode: "verify-full", RootCert: "/pg/ca.pem", ClientCert: "/pg/c.crt", ClientKey: "/pg/c.key"}},
		{"system roots", DatabaseConfig{DSN: "host=db sslrootcert=system"},
			DatabaseTLSFiles{SSLMode: "verify-full", RootCertSystem: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DatabaseTLSFilesOf(&tc.d)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDatabaseTLSFilesOf_RefusesWhatValidateRefuses(t *testing.T) {
	_, err := DatabaseTLSFilesOf(&DatabaseConfig{DSN: "host=db password=hunter2 sslmode=bogus"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2", "the dsn is never echoed")
}
