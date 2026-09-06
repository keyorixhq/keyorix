// egress_tls_srv_test.go — direct coverage for the two backend-specific
// gaps 2c/2d ask this fix to close explicitly: Mongo's TLS-default
// computation (mongodb+srv:// implies TLS; a plain mongodb:// URI does not
// unless tls=true/ssl=true) and the unix:// scheme refusal for Redis. Tests
// here are deliberately network-free wherever the assertion allows it (the
// TLS/scheme checks in both connectMongo/connectRedis run BEFORE any dial is
// attempted, so a bad input never needs a real connection to observe the
// refusal) — netutil/egress_test.go already covers Guard.ValidateSRVTargets'
// own logic thoroughly with a fake SRV resolver; this file only proves
// connectMongo actually WIRES that check in for a mongodb+srv:// URI.
package dynamic

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── mongoTLSEnabled (pure, no I/O) ───────────────

func TestMongoTLSEnabled_PlainMongoDBDefaultsToFalse(t *testing.T) {
	u, err := url.Parse("mongodb://admin:pass@db.example.net:27017/app")
	require.NoError(t, err)
	assert.False(t, mongoTLSEnabled(u), "a plain mongodb:// URI with no tls/ssl param must default to no TLS")
}

func TestMongoTLSEnabled_SRVSchemeDefaultsToTrue(t *testing.T) {
	u, err := url.Parse("mongodb+srv://admin:pass@cluster0.example.net/app")
	require.NoError(t, err)
	assert.True(t, mongoTLSEnabled(u), "mongodb+srv:// must default to TLS, matching the driver's own documented behaviour")
}

func TestMongoTLSEnabled_ExplicitTLSTrueOverridesPlainScheme(t *testing.T) {
	u, err := url.Parse("mongodb://admin:pass@db.example.net:27017/app?tls=true")
	require.NoError(t, err)
	assert.True(t, mongoTLSEnabled(u))
}

func TestMongoTLSEnabled_ExplicitTLSFalseOverridesSRVDefault(t *testing.T) {
	u, err := url.Parse("mongodb+srv://admin:pass@cluster0.example.net/app?tls=false")
	require.NoError(t, err)
	assert.False(t, mongoTLSEnabled(u), "an explicit tls=false must win over the mongodb+srv:// implicit default")
}

func TestMongoTLSEnabled_SSLParamAlias(t *testing.T) {
	u, err := url.Parse("mongodb://admin:pass@db.example.net:27017/app?ssl=true")
	require.NoError(t, err)
	assert.True(t, mongoTLSEnabled(u), "ssl=true is the legacy alias for tls=true")
}

// ──────────────────────────── connectMongo TLS enforcement ─────────────────
//
// These are network-free: guard.RequireTLS runs before connectMongo ever
// calls options.Client().ApplyURI/mongo.Connect, so a plaintext mongodb://
// URI is refused without attempting any connection at all.

func TestConnectMongo_RefusesPlaintextByDefault(t *testing.T) {
	_, err := connectMongo(context.Background(), "mongodb://admin:pass@db.example.net:27017/app", true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use TLS")
}

func TestConnectMongo_AllowInsecureTransportOptsOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// allowPrivateNetwork: true and a literal, non-routable TEST-NET-3 address
	// (RFC 5737) keep this bounded and DNS-free -- the connection itself will
	// still fail (nothing is listening), but NOT via the TLS guard.
	_, err := connectMongo(ctx, "mongodb://admin:pass@203.0.113.1:1/app", true, true)
	require.Error(t, err, "still fails -- nothing is listening -- but NOT via the TLS guard")
	assert.NotContains(t, err.Error(), "must use TLS")
}

// TestConnectMongo_SRVSchemeValidatesTargetsBeforeConnecting proves
// connectMongo actually wires Guard.ValidateSRVTargets in for a
// mongodb+srv:// URI when allowPrivateNetwork is false (the default) --
// the one piece netutil's own fake-resolver tests can't reach, since they
// exercise Guard directly rather than connectMongo's wiring of it. An empty
// host name resolves via ONE real (but fast: ~20ms measured, and guaranteed
// negative, RFC-1035-invalid) SRV query rather than a fabricated hostname,
// to avoid depending on a specific external domain's behaviour; bounded by a
// short context regardless.
func TestConnectMongo_SRVSchemeValidatesTargetsBeforeConnecting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, "mongodb+srv:///app", false, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SRV")
}

// TestConnectMongo_SRVValidationSkippedWhenAllowPrivateNetwork proves the
// explicit opt-out disables the SRV pre-check too, not just the per-dial
// guard -- mirrors TestPostgresEngine_Issue_AllowPrivateNetworkOptsOut.
func TestConnectMongo_SRVValidationSkippedWhenAllowPrivateNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, "mongodb+srv://cluster0.invalid-test-domain-xyz.example/app", true, true)
	require.Error(t, err, "still fails -- mongo.Connect itself will reject or fail to reach this -- but NOT via the SRV guard")
	assert.NotContains(t, err.Error(), "SRV target")
}

// ──────────────────────────── connectRedis scheme/TLS enforcement ─────────
//
// Also network-free: redis.ParseURL + the scheme/TLS checks are pure/local,
// run before connectRedis ever calls redis.NewClient/client.Ping.

func TestConnectRedis_RefusesUnixScheme(t *testing.T) {
	_, err := connectRedis(context.Background(), "unix:///var/run/redis/redis.sock?db=0", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unix")
}

func TestConnectRedis_RefusesPlaintextByDefault(t *testing.T) {
	_, err := connectRedis(context.Background(), "redis://admin:pass@db.example.net:6379/0", true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use TLS")
}

func TestConnectRedis_RedissSchemeSatisfiesTLSRequirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// rediss:// satisfies RequireTLS, so the failure (nothing listening on
	// this literal, non-routable address) must NOT be the TLS guard.
	_, err := connectRedis(ctx, "rediss://admin:pass@203.0.113.1:1/0", true, false)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "must use TLS")
}

func TestConnectRedis_AllowInsecureTransportOptsOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := connectRedis(ctx, "redis://admin:pass@203.0.113.1:1/0", true, true)
	require.Error(t, err, "still fails -- nothing is listening -- but NOT via the TLS guard")
	assert.NotContains(t, err.Error(), "must use TLS")
}
