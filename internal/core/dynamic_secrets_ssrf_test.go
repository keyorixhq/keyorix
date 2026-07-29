package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- parseDSNHost -------------------------------------------------------------

func TestParseDSNHost_URLForms(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
	}{
		{"postgres://admin:pass@db.example.com:5432/app", "db.example.com"},
		{"mysql://user:pass@mysql.internal:3306/db", "mysql.internal"},
		{"mongodb://user:pass@mongo.internal:27017/db", "mongo.internal"},
		{"redis://user:pass@redis.internal:6379/0", "redis.internal"},
		// IPv4 literal
		{"postgres://admin:pass@10.0.0.5:5432/app", "10.0.0.5"},
		// IPv6 literal (bracketed)
		{"postgres://admin:pass@[::1]:5432/app", "::1"},
	}
	for _, tc := range cases {
		got := parseDSNHost(tc.dsn)
		assert.Equal(t, tc.want, got, "DSN: %s", tc.dsn)
	}
}

func TestParseDSNHost_PostgresKeyValue(t *testing.T) {
	dsn := "host=db.internal port=5432 user=admin dbname=app sslmode=require"
	assert.Equal(t, "db.internal", parseDSNHost(dsn))

	dsnIP := "host=10.0.0.5 port=5432 user=admin dbname=app"
	assert.Equal(t, "10.0.0.5", parseDSNHost(dsnIP))
}

func TestParseDSNHost_MySQLTCPWrapper(t *testing.T) {
	dsn := "admin:pass@tcp(db.internal:3306)/app"
	assert.Equal(t, "db.internal", parseDSNHost(dsn))

	dsnAlt := "admin:pass@(db.internal:3306)/app"
	assert.Equal(t, "db.internal", parseDSNHost(dsnAlt))

	dsnIP := "admin:pass@tcp(192.168.1.10:3306)/app"
	assert.Equal(t, "192.168.1.10", parseDSNHost(dsnIP))
}

func TestParseDSNHost_UnrecognisedReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", parseDSNHost(""))
	assert.Equal(t, "", parseDSNHost("not-a-dsn"))
}

// -- validateAdminDSNHost -----------------------------------------------------

func TestValidateAdminDSNHost_PrivateLiteralIPRejected(t *testing.T) {
	cases := []struct {
		desc string
		dsn  string
	}{
		{"RFC-1918 10/8", "postgres://admin:pass@10.0.0.5:5432/app"},
		{"RFC-1918 172.16/12", "postgres://admin:pass@172.16.0.1:5432/app"},
		{"RFC-1918 192.168/16", "postgres://admin:pass@192.168.1.1:5432/app"},
		{"loopback 127.0.0.1", "postgres://admin:pass@127.0.0.1:5432/app"},
		{"link-local 169.254.x.x", "postgres://admin:pass@169.254.169.254:5432/app"},
		{"shared CGN 100.64.x.x", "postgres://admin:pass@100.64.0.1:5432/app"},
		{"key-value private", "host=10.1.2.3 port=5432 user=admin dbname=app"},
		{"mysql tcp private", "admin:pass@tcp(192.168.0.5:3306)/app"},
	}
	for _, tc := range cases {
		err := validateAdminDSNHost(tc.dsn)
		assert.Error(t, err, "should reject private IP (%s): %s", tc.desc, tc.dsn)
		if err != nil {
			assert.Contains(t, err.Error(), "private or link-local")
		}
	}
}

func TestValidateAdminDSNHost_PublicIPAllowed(t *testing.T) {
	dsn := "postgres://admin:pass@203.0.113.5:5432/app" // TEST-NET, globally routable
	require.NoError(t, validateAdminDSNHost(dsn))
}

func TestValidateAdminDSNHost_UnresolvableHostAllowed(t *testing.T) {
	// A hostname that can't be DNS-resolved at register time — fail-open so that
	// private-segment targets (reachable from Keyorix but not from DNS resolvers
	// it happens to use at startup) aren't locked out without AllowPrivateNetworkTargets.
	dsn := "postgres://admin:pass@this-hostname-does-not-exist.example.invalid:5432/app"
	require.NoError(t, validateAdminDSNHost(dsn))
}

func TestValidateAdminDSNHost_UnrecognisedDSNAllowed(t *testing.T) {
	// Unrecognised DSN format → host extraction fails → skip check (can't validate).
	require.NoError(t, validateAdminDSNHost("not-a-dsn"))
}

// -- CreateDynamicSecretConfig SSRF guard integration -------------------------

func TestDynamicSecrets_CreateConfig_SSRFGuardRejectsPrivateIP(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	// Private IP in the DSN must be rejected by the SSRF guard (default: guard ON).
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name:          "ssrf-test",
		ProjectID:     1,
		EnvironmentID: 2,
		BackendType:   "postgres",
		AdminDSN:      "postgres://admin:pass@10.0.0.5:5432/app",
		CreatedBy:     "alice",
		ActorID:       testAdminActorID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private or link-local")
}

func TestDynamicSecrets_CreateConfig_SSRFGuardBypassed(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	// Opt in to allow private targets — the private IP must now be accepted.
	c.SetDynamicAllowPrivateTargets(true)

	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name:          "ssrf-bypass",
		ProjectID:     1,
		EnvironmentID: 2,
		BackendType:   "postgres",
		AdminDSN:      "postgres://admin:pass@10.0.0.5:5432/app",
		CreatedBy:     "alice",
		ActorID:       testAdminActorID,
	})
	require.NoError(t, err)
	assert.NotZero(t, cfg.ID)
}

func TestDynamicSecrets_CreateConfig_SSRFGuardLinkLocal(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	// 169.254.169.254 is the cloud IMDS endpoint — should be blocked.
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name:          "imds-attempt",
		ProjectID:     1,
		EnvironmentID: 2,
		BackendType:   "postgres",
		AdminDSN:      "postgres://admin:pass@169.254.169.254:5432/steal-imds",
		CreatedBy:     "alice",
		ActorID:       testAdminActorID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private or link-local")
}
