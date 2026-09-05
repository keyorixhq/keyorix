package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Load("") must honour KEYORIX_CONFIG_PATH, including an absolute path (the
// container-deployment case the production compose relies on).
func TestLoadUsesConfigPathEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "production.yaml")
	require.NoError(t, os.WriteFile(p, []byte("locale:\n  language: fr\n"), 0600))

	t.Setenv("KEYORIX_CONFIG_PATH", p)
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "fr", cfg.Locale.Language)
}

// An explicit path argument wins over KEYORIX_CONFIG_PATH.
func TestLoadExplicitPathBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env.yaml")
	argFile := filepath.Join(dir, "arg.yaml")
	require.NoError(t, os.WriteFile(envFile, []byte("locale:\n  language: fr\n"), 0600))
	require.NoError(t, os.WriteFile(argFile, []byte("locale:\n  language: de\n"), 0600))

	t.Setenv("KEYORIX_CONFIG_PATH", envFile)
	cfg, err := Load(argFile)
	require.NoError(t, err)
	assert.Equal(t, "de", cfg.Locale.Language)
}

// A missing config file returns an error rather than a zero-value config.
func TestLoadMissingFile(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	_, err := Load("")
	require.Error(t, err)
}

// An absent session block falls back to the historic 24h access window and no
// absolute ceiling, so existing installs keep their old behaviour.
func TestSessionConfigDefaults(t *testing.T) {
	var c SessionConfig // zero value = block absent
	assert.Equal(t, 24*time.Hour, c.GetAccessTTL())
	assert.Equal(t, time.Duration(0), c.GetAbsoluteTTL(), "no ceiling by default")
}

// A configured session block is parsed; invalid/non-positive values fall back to
// the access-TTL default and to "no ceiling" respectively.
func TestSessionConfigParsing(t *testing.T) {
	c := SessionConfig{AccessTTL: "30m", AbsoluteTTL: "12h"}
	assert.Equal(t, 30*time.Minute, c.GetAccessTTL())
	assert.Equal(t, 12*time.Hour, c.GetAbsoluteTTL())

	bad := SessionConfig{AccessTTL: "nonsense", AbsoluteTTL: "nonsense"}
	assert.Equal(t, 24*time.Hour, bad.GetAccessTTL(), "invalid access TTL → default")
	assert.Equal(t, time.Duration(0), bad.GetAbsoluteTTL(), "invalid absolute TTL → no ceiling")

	zero := SessionConfig{AbsoluteTTL: "0"}
	assert.Equal(t, time.Duration(0), zero.GetAbsoluteTTL(), `"0" → no ceiling`)
}

// TLS verification for the remote storage client is SECURE BY DEFAULT: an omitted
// tls_verify must not disable certificate validation on the secrets-manager API.
func TestRemoteConfig_VerifyTLS_SecureByDefault(t *testing.T) {
	// Unset (the dangerous case before the fix) → verification ON.
	unset := &RemoteConfig{BaseURL: "https://x"}
	assert.True(t, unset.VerifyTLS(), "omitted tls_verify must verify")

	// A config file that omits the key parses to nil → verify.
	var loaded Config
	require.NoError(t, yamlUnmarshalForTest(t, "storage:\n  type: remote\n  remote:\n    base_url: https://x\n", &loaded))
	require.NotNil(t, loaded.Storage.Remote)
	assert.True(t, loaded.Storage.Remote.VerifyTLS(), "parsed-without-key must verify")

	// Explicit opt-out is honoured.
	assert.False(t, (&RemoteConfig{TLSVerify: BoolPtr(false)}).VerifyTLS())
	// Explicit true verifies.
	assert.True(t, (&RemoteConfig{TLSVerify: BoolPtr(true)}).VerifyTLS())
}

func yamlUnmarshalForTest(t *testing.T, y string, c *Config) error {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	loaded, err := Load(p)
	if err != nil {
		return err
	}
	*c = *loaded
	return nil
}

// gRPC TLS auto_cert has no ACME backing (it would build a certless config and fail every
// handshake), so Validate must reject it rather than start a server that cannot serve.
func TestValidate_RejectsGRPCAutoCert(t *testing.T) {
	c := &Config{}
	c.Server.GRPC.TLS.Enabled = true
	c.Server.GRPC.TLS.AutoCert = true
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "auto_cert")
}

// A bare "*" in allowed_origins would match every Origin header — Validate must
// reject it at startup rather than let an operator silently defeat the CORS
// allowlist (finding #113).
func TestValidate_RejectsWildcardAllowedOrigin(t *testing.T) {
	c := &Config{}
	c.Server.HTTP.AllowedOrigins = []string{"https://app.example.com", "*"}
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "allowed_origins")
	require.Contains(t, err.Error(), "\"*\"")
}

// Malformed entries (no scheme, a path/query/fragment tacked on, or a non-http(s)
// scheme) are not valid Origin values and must be rejected rather than silently
// never matching any real Origin header at request time.
func TestValidate_RejectsMalformedAllowedOrigin(t *testing.T) {
	cases := []string{
		"example.com",                  // no scheme
		"https://app.example.com/path", // has a path
		"https://app.example.com?x=1",  // has a query
		"ftp://app.example.com",        // non-http(s) scheme
		"",                             // empty
	}
	for _, origin := range cases {
		c := &Config{}
		c.Server.HTTP.AllowedOrigins = []string{origin}
		err := c.Validate()
		require.Errorf(t, err, "expected %q to be rejected", origin)
		require.Contains(t, err.Error(), "allowed_origins")
	}
}

// A well-formed explicit allowlist (the common case) must still validate cleanly.
func TestValidate_AcceptsExplicitAllowedOrigins(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = "/tmp/keyorix.db"
	c.Server.HTTP.AllowedOrigins = []string{"https://app.example.com", "http://localhost:3000"}
	require.NoError(t, c.Validate())
}

// #463: an unrecognized storage.type (e.g. a typo like "postgres_typo") used to
// be silently accepted by Validate and fall through to the SQLite default
// everywhere downstream — in a multi-replica HA deployment intending shared
// Postgres/remote storage, that produces per-replica split-brain SQLite
// instances with no operator-visible signal. Validate must reject it clearly.
// ADR-083: storage.type: remote is a CLI/client mode only — it cannot back a
// server that serves HTTP or gRPC API routes, since RemoteStorage never
// implements the RBAC primitives AuthorizePrincipal needs (GetUserRoleIDsAt,
// GetUserGroupRoleIDsAt, RoleSetHasPermission), so every permission check would
// fail closed for every caller.
func TestValidate_RejectsRemoteStorageWithHTTPEnabled(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "remote"
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.Port = "8080"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.type: remote")
	require.Contains(t, err.Error(), "ADR-083")
}

func TestValidate_RejectsRemoteStorageWithGRPCEnabled(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "remote"
	c.Server.GRPC.Enabled = true
	c.Server.GRPC.Port = "9090"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.type: remote")
	require.Contains(t, err.Error(), "ADR-083")
}

func TestValidate_RejectsRemoteStorageWithBothHTTPAndGRPCEnabled(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "remote"
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.Port = "8080"
	c.Server.GRPC.Enabled = true
	c.Server.GRPC.Port = "9090"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.type: remote")
}

// G80 follow-up (2026-08-24), correcting this test's own prior premise: it used
// to assert that storage.type: remote with neither server flag enabled must
// validate cleanly, reasoning "that's exactly what a CLI in client mode looks
// like." That reasoning doesn't hold: Config.Validate (and therefore this
// function) has NO caller anywhere under internal/cli — verified by a
// repo-wide search — the CLI's own "connected mode" validates a narrower,
// distinct internal/storage/remote.Config, never reaches this code at all. So
// there is no legitimate CLI case being protected here. What IS reachable with
// both server flags false: server/main.go's startSchedulers (main.go:157) runs
// unconditionally on every boot, independent of server.http.enabled/
// server.grpc.enabled — three of its 17 schedulers (anomaly_detection,
// login_attempt_prune, mfa_stepup_grant_prune) have no enable flag at all and
// always run. That's a real, bootable "scheduler-only worker" server shape
// this check was missing entirely. Now rejected unconditionally.
func TestValidate_RejectsRemoteStorageWithNoServerEnabled(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "remote"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.type: remote")
	require.Contains(t, err.Error(), "ADR-083")
}

// A validation change here must be scoped to storage.type: remote specifically —
// local/postgres storage with servers enabled is the ordinary, fully-supported
// deployment shape and must remain unaffected.
func TestValidate_AcceptsLocalAndPostgresStorageWithServersEnabled(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = "/tmp/keyorix.db"
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.Port = "8080"
	c.Server.GRPC.Enabled = true
	c.Server.GRPC.Port = "9090"
	require.NoError(t, c.Validate())

	c2 := &Config{}
	c2.Storage.Type = "postgres"
	c2.Storage.Database.DSN = "postgres://user:pass@localhost/db"
	c2.Server.HTTP.Enabled = true
	c2.Server.HTTP.Port = "8080"
	c2.Server.GRPC.Enabled = true
	c2.Server.GRPC.Port = "9090"
	require.NoError(t, c2.Validate())
}

func TestValidate_RejectsUnknownStorageType(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "postgres_typo"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.type")
	require.Contains(t, err.Error(), "postgres_typo")
}

// TestValidate_RejectsBlankStorageType is #G-blank-storage-default: a blank
// storage.type used to be bucketed with "local"/"sqlite" (accepted, as long as
// database.path was set) — silently identical to an operator who explicitly
// chose local storage. It must now be a hard error from this shared validator,
// the same as an unrecognized type, since Config.Validate is used by both the
// server and (indirectly, via fixtures) tests that must not get a free local
// default. The one legitimate "no storage: block = local SQLite" deployment
// shape is preserved by server/main.go explicitly setting Storage.Type =
// "local" BEFORE ever calling Validate() — not by this function.
func TestValidate_RejectsBlankStorageType(t *testing.T) {
	c := &Config{}
	c.Storage.Type = ""
	c.Storage.Database.Path = "/tmp/keyorix.db"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.type is not set")
}

// Companion to TestValidate_RejectsUnknownStorageType: every genuinely-supported
// storage.type value must still validate cleanly — a validation change that's
// too aggressive is as dangerous as one that's too permissive.
func TestValidate_AcceptsValidStorageTypes(t *testing.T) {
	// G80 follow-up (2026-08-24): "remote" deliberately excluded from this list --
	// it's a genuinely-supported storage.type value for the CLI, but Config.Validate
	// (this function) is never reached by the CLI (see
	// TestValidate_RejectsRemoteStorageWithNoServerEnabled's comment) and now rejects
	// "remote" unconditionally, since it's the one storage type this validator's own
	// caller (server/main.go) can never legitimately back a server process with.
	//
	// "" is also deliberately excluded: see TestValidate_RejectsBlankStorageType
	// (#G-blank-storage-default) -- a blank storage.type is now a hard error here.
	for _, storageType := range []string{"local", "sqlite", "postgres", "postgresql"} {
		c := &Config{}
		c.Storage.Type = storageType
		switch storageType {
		case "postgres", "postgresql":
			c.Storage.Database.DSN = "postgres://user:pass@localhost/db"
		case "local", "sqlite":
			c.Storage.Database.Path = "/tmp/keyorix.db"
		}
		err := c.Validate()
		require.NoErrorf(t, err, "storage.type %q should be accepted", storageType)
	}
}

// TestValidate_SqliteAliasForLocal is #1640's regression: configs/keyorix.yaml.tpl
// documents storage.type: sqlite, but until this fix only "local" validated —
// copying the shipped template verbatim and leaving it as documented failed
// outright at startup.
func TestValidate_SqliteAliasForLocal(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "sqlite"
	c.Storage.Database.Path = "/tmp/keyorix.db"
	require.NoError(t, c.Validate())
}
