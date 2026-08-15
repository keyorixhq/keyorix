package dynamic

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Backends(t *testing.T) {
	pg, err := New("postgres", false)
	require.NoError(t, err)
	assert.Equal(t, "postgres", pg.BackendType())

	my, err := New("mysql", false)
	require.NoError(t, err)
	assert.Equal(t, "mysql", my.BackendType())

	mg, err := New("mongodb", false)
	require.NoError(t, err)
	assert.Equal(t, "mongodb", mg.BackendType())

	rd, err := New("redis", false)
	require.NoError(t, err)
	assert.Equal(t, "redis", rd.BackendType())

	for _, bt := range []string{"aws-sts", "gcp", "azure", "kubernetes"} {
		eng, err := New(bt, false)
		require.NoError(t, err)
		assert.Equal(t, bt, eng.BackendType())
		assert.True(t, eng.IsEphemeralBackend(), "%s mints self-expiring credentials", bt)
		assert.True(t, eng.SupportsNativeExpiry(), "%s expiry enforced by the provider", bt)
	}

	_, err = New("cassandra", false)
	require.Error(t, err, "an unsupported backend is rejected")
}

func TestParseMongoRoles(t *testing.T) {
	// Empty template → empty roles array (a user with no privileges).
	roles, err := parseMongoRoles("")
	require.NoError(t, err)
	assert.Empty(t, roles)

	// A role spec with built-in (string) and {role, db} entries parses through.
	roles, err = parseMongoRoles(`{"roles": [{"role": "readWrite", "db": "app"}, "clusterMonitor"]}`)
	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.Equal(t, "clusterMonitor", roles[1])

	// Non-JSON is rejected with a helpful message.
	_, err = parseMongoRoles("GRANT SELECT ON app.* TO {{name}}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be JSON")

	// Valid JSON object without a roles array is rejected.
	_, err = parseMongoRoles(`{"db": "app"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles")
}

func TestMongoEngine_RevokeRejectsUnsafeRole(t *testing.T) {
	// Defense-in-depth: a tampered role name is rejected before any connection.
	err := (&MongoEngine{}).Revoke(context.Background(), "mongodb://admin:p@h:27017/", "evil'; drop")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe dynamic-secret username")
}

func TestMongoEngine_InvalidURIRejected(t *testing.T) {
	// A malformed URI is rejected at connect time, before any user is created.
	_, _, err := (&MongoEngine{}).Issue(context.Background(), "http://not-a-mongo-uri", `{"roles": []}`, 0)
	require.Error(t, err)
}

func TestMySQLAccountRef(t *testing.T) {
	// The {{name}} substitution renders a properly-quoted account reference, and a
	// quote-free username (as randString produces) cannot escape the quotes.
	ref := mysqlAccountRef("kx_dyn_abc123")
	assert.Equal(t, "'kx_dyn_abc123'@'%'", ref)

	grant := strings.ReplaceAll("GRANT SELECT ON app.* TO {{name}};", "{{name}}", ref)
	assert.Equal(t, "GRANT SELECT ON app.* TO 'kx_dyn_abc123'@'%';", grant)
}

func TestAssertSafeUsername(t *testing.T) {
	require.NoError(t, assertSafeUsername("kx_dyn_abc123"))
	for _, bad := range []string{"", "kx'dyn", "kx`dyn", "kx dyn", "kx-dyn", "KXDYN", "kx\\dyn"} {
		assert.Error(t, assertSafeUsername(bad), "must reject %q", bad)
	}
}

func TestMySQLEngine_RevokeRejectsUnsafeRole(t *testing.T) {
	// Defense-in-depth: a tampered/unsafe role name from storage is rejected before
	// any SQL is constructed or any connection is opened.
	err := (&MySQLEngine{}).Revoke(context.Background(), "admin:p@tcp(h:3306)/", "evil'; DROP")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe dynamic-secret username")
}

func TestMySQLEngine_InvalidDSNRejected(t *testing.T) {
	e := &MySQLEngine{}
	// A malformed DSN is rejected by ParseDSN before any connection attempt.
	_, _, err := e.Issue(context.Background(), "not a valid dsn at all", "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mysql admin DSN")
}

func TestParseRedisACLRules(t *testing.T) {
	// Empty template → no rules (a user that can auth but has no permissions).
	assert.Empty(t, parseRedisACLRules(""))
	assert.Empty(t, parseRedisACLRules("   \n\t "))

	// Whitespace-separated tokens are split into discrete ACL args.
	assert.Equal(t, []string{"~app:*", "+@read", "+@write"}, parseRedisACLRules("~app:* +@read +@write"))
	// Extra/odd whitespace collapses.
	assert.Equal(t, []string{"allkeys", "+@all"}, parseRedisACLRules("  allkeys   +@all  "))
}

func TestRedisEngine_Metadata(t *testing.T) {
	e := &RedisEngine{}
	assert.Equal(t, "redis", e.BackendType())
	assert.False(t, e.SupportsNativeExpiry(), "Redis ACL users have no native expiry — sweeper enforces TTL")
}

func TestRedisEngine_RevokeRejectsUnsafeRole(t *testing.T) {
	// Defense-in-depth: a tampered role name is rejected before any connection.
	err := (&RedisEngine{}).Revoke(context.Background(), "redis://:p@h:6379/0", "evil-user'")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe dynamic-secret username")
}

func TestRedisEngine_InvalidURIRejected(t *testing.T) {
	// A malformed URI is rejected at connect time, before any user is created.
	_, _, err := (&RedisEngine{}).Issue(context.Background(), "http://not-a-redis-uri", "+@read", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis admin URI")
}

func TestRandString_QuoteFreeAlphabet(t *testing.T) {
	// The credential alphabet must never contain a quote/backslash, which is what
	// makes the fmt.Sprintf'd SQL safe in both engines.
	s, err := randString(256)
	require.NoError(t, err)
	require.Len(t, s, 256)
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Fatalf("unexpected character %q in randString output", r)
		}
	}
}
