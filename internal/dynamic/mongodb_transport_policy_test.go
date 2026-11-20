package dynamic

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// #4374: admin_dsn is project-admin input, and dynamic_secrets.insecure_allow_
// plaintext_dynamic_secret_transport is the operator's transport policy. A mongodb
// admin_dsn must not be able to undo it: tls=true satisfies the TLS requirement, and
// tlsInsecure=true (alias sslInsecure) then turns certificate and hostname
// verification off. Same class as the Redis skip_verify refusal (#4372/#4373).

const mongoInsecureBase = "mongodb://admin:pass@203.0.113.1:1/app"

func TestConnectMongo_RefusesInsecureTLSOptions(t *testing.T) {
	for _, d := range []string{
		mongoInsecureBase + "?tls=true&tlsInsecure=true",
		mongoInsecureBase + "?ssl=true&sslInsecure=true",
		mongoInsecureBase + "?tls=true&TLSINSECURE=true",                   // the driver lower-cases option names
		mongoInsecureBase + "?tls=true&tlsInsecure=false&tlsInsecure=true", // the driver takes the last value
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := connectMongo(ctx, d, true, false)
		cancel()
		var fe *dsn.ForbiddenOptionError
		require.ErrorAs(t, err, &fe, d)
		assert.Equal(t, "tlsInsecure", fe.Option, d)
		assert.Equal(t, "mongodb", fe.Backend, d)
		assert.NotContains(t, err.Error(), "pass", "the error must not quote the DSN")
	}
}

func TestConnectMongo_InsecureTLSFalseIsNotRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, mongoInsecureBase+"?tls=true&tlsInsecure=false&serverSelectionTimeoutMS=300", true, false)
	require.Error(t, err) // nothing listens, but this is not a policy refusal
	var fe *dsn.ForbiddenOptionError
	assert.False(t, errors.As(err, &fe), "%v", err)
}

// With the operator's opt-in the option is allowed, and the connection says so in the
// log (as a plaintext connection does).
func TestConnectMongo_InsecureTLSAllowedWhenOperatorOptsIn(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, mongoInsecureBase+"?tls=true&tlsInsecure=true&serverSelectionTimeoutMS=300", true, true)
	require.Error(t, err) // nothing listens
	var fe *dsn.ForbiddenOptionError
	assert.False(t, errors.As(err, &fe), "%v", err)
	assert.Contains(t, logs.String(), "WARNING: mongodb admin_dsn")
	assert.Contains(t, logs.String(), "not verified")
	assert.NotContains(t, logs.String(), "pass")
}

// The driver lower-cases option names; the TLS check read them as written, so a
// mongodb+srv admin_dsn (TLS by default) could say TLS=false and connect in clear.
// Network-free: the refusal comes before the driver parses the URI (which, for an
// srv URI, resolves DNS).
func TestConnectMongo_TLSOffSpellingsCannotDowngrade(t *testing.T) {
	for _, d := range []string{
		"mongodb+srv://admin:pass@cluster0.example.net/app?TLS=false",
		"mongodb+srv://admin:pass@cluster0.example.net/app?SSL=false",
		"mongodb+srv://admin:pass@cluster0.example.net/app?appName=x&Tls=false",
		"mongodb://admin:pass@203.0.113.1:1/app?TLS=false",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := connectMongo(ctx, d, true, false)
		cancel()
		require.Error(t, err, d)
		assert.Contains(t, err.Error(), "must use TLS", d)
	}
}

// The driver pinned in go.mod does not read tlsAllowInvalidCertificates or
// tlsAllowInvalidHostnames (they are kept as unknown options and do nothing). This
// test is the class guard for the day it does: whatever the DSN spells, either the
// driver ends with verification on, or connectMongo refuses it.
func TestConnectMongo_NoSpellingTurnsVerificationOffUnrefused(t *testing.T) {
	for _, q := range []string{
		"tlsAllowInvalidCertificates=true",
		"tlsAllowInvalidHostnames=true",
		"sslAllowInvalidCertificates=true",
		"sslAllowInvalidHostnames=true",
		"tlsInsecure=true",
		"sslInsecure=true",
	} {
		d := mongoInsecureBase + "?tls=true&" + q
		opts := options.Client().ApplyURI(d)
		driverSkipsVerify := opts.Validate() == nil && opts.TLSConfig != nil && opts.TLSConfig.InsecureSkipVerify

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := connectMongo(ctx, d, true, false)
		cancel()
		var fe *dsn.ForbiddenOptionError
		refused := errors.As(err, &fe)
		if driverSkipsVerify {
			assert.True(t, refused, "%s: the driver would skip verification and connectMongo did not refuse it: %v", q, err)
		} else {
			assert.False(t, refused, "%s: the pinned driver ignores it, a refusal here is a surprise: %v", q, err)
		}
	}
}

// Revoke drops tlsInsecure instead of refusing, with certificate verification kept
// on: users have no native expiry, so a refused revoke would leave them live.
func TestMongoEngine_Revoke_InsecureTLSOptionIsDroppedNotRefused(t *testing.T) {
	e := &MongoEngine{allowPrivateNetwork: true}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := e.Revoke(ctx, mongoInsecureBase+"?tls=true&tlsInsecure=true&serverSelectionTimeoutMS=300", "kx_dyn_test")
	require.Error(t, err) // nothing listens
	var fe *dsn.ForbiddenOptionError
	assert.False(t, errors.As(err, &fe), "revoke must not refuse tlsInsecure: %v", err)
	assert.Contains(t, err.Error(), "tlsInsecure")
	assert.True(t, strings.Contains(err.Error(), "verified"), "the error names that verification stayed on: %v", err)
	assert.NotContains(t, err.Error(), "pass", "the error must not quote the DSN")
}

// mongoTLSEnabled reads the options as the driver does: names case-insensitive,
// options split on '&' and ';', the last tls/ssl value wins.
func TestMongoTLSEnabled_ReadsOptionsLikeTheDriver(t *testing.T) {
	for d, want := range map[string]bool{
		"mongodb+srv://h/app?TLS=false":           false,
		"mongodb+srv://h/app?SSL=false":           false,
		"mongodb+srv://h/app?appName=x;Tls=false": false,
		"mongodb+srv://h/app?%74ls=false":         false, // percent-encoded key byte
		"mongodb+srv://h/app?tls=true":            true,
		"mongodb+srv://h/app":                     true,
		"mongodb://h/app?TLS=true":                true,
		"mongodb://h/app?tls=false&TLS=true":      true,
		"mongodb://h/app?tls=true;tls=false":      false,
		"mongodb://h/app?tls=TRUE":                false, // the driver rejects it; never counted as TLS
		"mongodb://h/app":                         false,
	} {
		u, err := url.Parse(d)
		require.NoError(t, err, d)
		assert.Equal(t, want, mongoTLSEnabled(u), d)
	}
}
