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

func TestParseDSNHost_KubernetesJSONConfig(t *testing.T) {
	dsn := `{"api_server":"https://k8s.internal:6443","token":"tok","ca_cert":"cert"}`
	assert.Equal(t, "k8s.internal", parseDSNHost(dsn))

	dsnIP := `{"api_server":"https://10.0.0.9:6443","token":"tok","ca_cert":"cert"}`
	assert.Equal(t, "10.0.0.9", parseDSNHost(dsnIP))

	// No api_server (in-cluster mode) — nothing to extract, not a validation gap:
	// the actual host then comes from KUBERNETES_SERVICE_HOST/PORT, which isn't
	// attacker-influenceable.
	assert.Equal(t, "", parseDSNHost(`{"token":"tok","ca_cert":"cert"}`))
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
		{"kubernetes JSON config, private IP", `{"api_server":"https://10.0.0.9:6443","token":"tok","ca_cert":"cert"}`},
		{"kubernetes JSON config, cloud IMDS", `{"api_server":"http://169.254.169.254","token":"tok","ca_cert":"cert"}`},
	}
	for _, tc := range cases {
		err := validateAdminDSNHost(tc.dsn)
		assert.Error(t, err, "should reject private IP (%s): %s", tc.desc, tc.dsn)
		if err != nil {
			assert.Contains(t, err.Error(), "private or link-local")
		}
	}
}

// net.ParseIP doesn't accept RFC 4007 zone-ID syntax ("fe80::1%eth0"), so a
// zone-qualified link-local literal must still be recognised (by stripping the zone
// and retrying ParseIP) rather than falling through to net.LookupHost — which errors
// on a zone-qualified address and would otherwise land in the "unresolvable, skip"
// branch, silently bypassing the fe80::/10 blocklist entry.
func TestValidateAdminDSNHost_ZoneQualifiedLinkLocalRejected(t *testing.T) {
	cases := []struct {
		desc string
		dsn  string
	}{
		{"key-value zone-qualified link-local", "host=fe80::1%eth0 port=5432 user=admin dbname=app"},
		{"mysql tcp zone-qualified link-local", "admin:pass@tcp(fe80::1%eth0:3306)/app"},
	}
	for _, tc := range cases {
		err := validateAdminDSNHost(tc.dsn)
		assert.Error(t, err, "should reject zone-qualified link-local (%s): %s", tc.desc, tc.dsn)
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

func TestDynamicSecrets_CreateConfig_SSRFGuardRejectsKubernetesPrivateAPIServer(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()

	// The kubernetes backend's admin_dsn is a JSON blob ({"api_server": ...}), not a
	// URL/wrapper/key-value DSN string. Before parseDSNHost learned to parse it, this
	// silently bypassed the SSRF guard entirely for this one backend type -- a
	// project-scoped admin (requireDynamicSecretAdminAuthority, not a system-level
	// admin) could point a kubernetes dynamic-secrets config's api_server at the
	// cloud IMDS endpoint or any other private-network service and mint a live
	// ServiceAccount token via the TokenRequest API against it.
	_, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name:          "k8s-imds-attempt",
		ProjectID:     1,
		EnvironmentID: 2,
		BackendType:   "kubernetes",
		AdminDSN:      `{"api_server":"http://169.254.169.254","token":"tok","ca_cert":"cert"}`,
		CreatedBy:     "alice",
		ActorID:       testAdminActorID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private or link-local")
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
