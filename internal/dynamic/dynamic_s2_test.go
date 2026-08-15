package dynamic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
)

// ──────────────────────────── PostgresEngine metadata ──────────────────────

func TestPostgresEngine_Metadata(t *testing.T) {
	e := &PostgresEngine{}
	assert.Equal(t, "postgres", e.BackendType())
	assert.True(t, e.SupportsNativeExpiry(), "Postgres roles carry VALID UNTIL")
	assert.False(t, e.IsEphemeralBackend())
	assert.True(t, e.RevokeInvalidatesCredential("any"), "DROP ROLE removes the account immediately")
}

func TestPostgresEngine_Issue_ConnectError(t *testing.T) {
	e := &PostgresEngine{}
	_, _, err := e.Issue(context.Background(), "host=nonexistent user=x dbname=x sslmode=disable connect_timeout=1", "", time.Second)
	require.Error(t, err)
}

func TestPostgresEngine_Revoke_ConnectError(t *testing.T) {
	e := &PostgresEngine{}
	err := e.Revoke(context.Background(), "host=nonexistent user=x dbname=x sslmode=disable connect_timeout=1", "kx_dyn_test")
	require.Error(t, err)
}

func TestPostgresEngine_Renew_ConnectError(t *testing.T) {
	e := &PostgresEngine{}
	err := e.Renew(context.Background(), "host=nonexistent user=x dbname=x sslmode=disable connect_timeout=1", "kx_dyn_test", time.Now().Add(time.Hour))
	require.Error(t, err)
}

// TestPostgresEngine_Issue_DialTimeRefusesDNSRebind is the G48 regression: the
// admin_dsn's host is re-validated on every actual connection (Issue/
// Revoke/Renew), not just once when the config was created — a DNS-rebinding
// attacker whose hostname resolves to a private/link-local address AT DIAL
// TIME must be refused, even though an earlier check (e.g.
// validateAdminDSNHost at config-create time) might have seen a different
// answer. allowPrivateNetwork defaults to false (the PostgresEngine{} zero
// value), matching dynamic_secrets.allow_private_network_targets' default.
func TestPostgresEngine_Issue_DialTimeRefusesDNSRebind(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
		require.Equal(t, "rebind.postgres.example", host)
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}

	e := &PostgresEngine{} // allowPrivateNetwork: false (default / secure)
	_, _, err := e.Issue(context.Background(), "postgres://admin:pass@rebind.postgres.example:5432/app?sslmode=disable", "", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed address")
}

// TestPostgresEngine_Revoke_DialTimeRefusesDNSRebind mirrors the Issue test
// for the Revoke path.
func TestPostgresEngine_Revoke_DialTimeRefusesDNSRebind(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}

	e := &PostgresEngine{}
	err := e.Revoke(context.Background(), "postgres://admin:pass@rebind.postgres.example:5432/app?sslmode=disable", "kx_dyn_test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed address")
}

// TestPostgresEngine_Issue_AllowPrivateNetworkOptsOut proves the explicit
// operator opt-in (dynamic_secrets.allow_private_network_targets, mirrored
// per-engine as allowPrivateNetwork) disables the dial-time guard, exactly
// like it already disabled the config-create-time guard — a legitimately
// on-prem/private-network target must still be reachable.
func TestPostgresEngine_Issue_AllowPrivateNetworkOptsOut(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}

	e := &PostgresEngine{allowPrivateNetwork: true}
	_, _, err := e.Issue(context.Background(), "postgres://admin:pass@rebind.postgres.example:5432/app?sslmode=disable&connect_timeout=1", "", time.Minute)
	require.Error(t, err, "still fails — nothing is listening — but NOT via the SSRF guard")
	assert.NotContains(t, err.Error(), "disallowed address")
}

// ──────────────────────────── MySQLEngine metadata ─────────────────────────

func TestMySQLEngine_Metadata(t *testing.T) {
	e := &MySQLEngine{}
	assert.Equal(t, "mysql", e.BackendType())
	assert.False(t, e.SupportsNativeExpiry(), "MySQL users have no VALID UNTIL")
	assert.False(t, e.IsEphemeralBackend())
	assert.True(t, e.RevokeInvalidatesCredential("any"), "DROP USER removes the account immediately")
}

func TestMySQLEngine_Renew_Noop(t *testing.T) {
	e := &MySQLEngine{}
	require.NoError(t, e.Renew(context.Background(), "any", "kx_dyn_test", time.Now().Add(time.Hour)))
}

func TestMySQLEngine_Issue_InvalidDSN_Extra(t *testing.T) {
	e := &MySQLEngine{}
	_, _, err := e.Issue(context.Background(), "not-a-valid-mysql-dsn!!!", "", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mysql admin DSN")
}

func TestMySQLEngine_Revoke_InvalidDSN(t *testing.T) {
	e := &MySQLEngine{}
	// assertSafeUsername passes ("kx_dyn_abc"), then openMySQL fails on bad DSN.
	err := e.Revoke(context.Background(), "not-a-valid-mysql-dsn!!!", "kx_dyn_abc")
	require.Error(t, err)
}

// TestMySQLEngine_Issue_DialTimeRefusesDNSRebind is the G48 regression: the
// admin_dsn's host is re-validated on every actual connection, not just once
// when the config was created — a DNS-rebinding attacker whose hostname
// resolves to a private/link-local address AT DIAL TIME must be refused,
// even though an earlier check might have seen a different answer.
// allowPrivateNetwork defaults to false (the MySQLEngine{} zero value),
// matching dynamic_secrets.allow_private_network_targets' default.
func TestMySQLEngine_Issue_DialTimeRefusesDNSRebind(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
		require.Equal(t, "rebind.mysql.example", host)
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}

	e := &MySQLEngine{} // allowPrivateNetwork: false (default / secure)
	_, _, err := e.Issue(context.Background(), "admin:pass@tcp(rebind.mysql.example:3306)/app", "", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed address")
}

// TestMySQLEngine_Issue_AllowPrivateNetworkOptsOut proves the explicit
// operator opt-in disables the dial-time guard, mirroring
// TestPostgresEngine_Issue_AllowPrivateNetworkOptsOut.
func TestMySQLEngine_Issue_AllowPrivateNetworkOptsOut(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}

	e := &MySQLEngine{allowPrivateNetwork: true}
	_, _, err := e.Issue(context.Background(), "admin:pass@tcp(rebind.mysql.example:3306)/app?timeout=1s", "", time.Minute)
	require.Error(t, err, "still fails — nothing is listening — but NOT via the SSRF guard")
	assert.NotContains(t, err.Error(), "disallowed address")
}

// ──────────────────────────── MongoEngine metadata ─────────────────────────

func TestMongoEngine_Metadata(t *testing.T) {
	e := &MongoEngine{}
	assert.Equal(t, "mongodb", e.BackendType())
	assert.False(t, e.SupportsNativeExpiry(), "MongoDB users have no native expiry")
	assert.False(t, e.IsEphemeralBackend())
	assert.True(t, e.RevokeInvalidatesCredential("any"), "dropUser removes the account immediately")
}

func TestMongoEngine_Renew_Noop(t *testing.T) {
	e := &MongoEngine{}
	require.NoError(t, e.Renew(context.Background(), "any", "kx_dyn_test", time.Now().Add(time.Hour)))
}

func TestMongoEngine_Issue_InvalidRoles(t *testing.T) {
	e := &MongoEngine{}
	_, _, err := e.Issue(context.Background(), "mongodb://admin:pass@localhost:27017/", `{"not_roles": []}`, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles")
}

// ──────────────────────────── isMongoUserNotFound ──────────────────────────

func TestIsMongoUserNotFound_True(t *testing.T) {
	// Code 11 = UserNotFound
	err := mongo.CommandError{Code: 11, Name: "UserNotFound", Message: "user not found"}
	assert.True(t, isMongoUserNotFound(err))
}

func TestIsMongoUserNotFound_OtherCode(t *testing.T) {
	err := mongo.CommandError{Code: 13, Name: "Unauthorized", Message: "not authorized"}
	assert.False(t, isMongoUserNotFound(err))
}

func TestIsMongoUserNotFound_NonMongoError(t *testing.T) {
	assert.False(t, isMongoUserNotFound(errors.New("some other error")))
}

func TestIsMongoUserNotFound_ByName(t *testing.T) {
	// Name match even if code differs
	err := mongo.CommandError{Code: 99, Name: "UserNotFound", Message: "user not found"}
	assert.True(t, isMongoUserNotFound(err))
}

// ──────────────────────────── RedisEngine metadata ─────────────────────────

func TestRedisEngine_Metadata_Full(t *testing.T) {
	e := &RedisEngine{}
	assert.Equal(t, "redis", e.BackendType())
	assert.False(t, e.SupportsNativeExpiry())
	assert.False(t, e.IsEphemeralBackend())
	assert.True(t, e.RevokeInvalidatesCredential("any"), "ACL DELUSER removes the account immediately")
}

func TestRedisEngine_Renew_Noop(t *testing.T) {
	e := &RedisEngine{}
	require.NoError(t, e.Renew(context.Background(), "any", "kx_dyn_test", time.Now().Add(time.Hour)))
}

// ──────────────────────────── assertSafeUsername extras ────────────────────

func TestAssertSafeUsername_ValidWithUnderscore(t *testing.T) {
	// kx_dyn_<suffix> is the canonical format — must be safe.
	require.NoError(t, assertSafeUsername("kx_dyn_abc123xyz"))
}

func TestAssertSafeUsername_EmptyString(t *testing.T) {
	require.Error(t, assertSafeUsername(""))
}

// ──────────────────────────── parseMongoRoles extras ──────────────────────

func TestParseMongoRoles_WhitespaceOnly(t *testing.T) {
	// Whitespace-only template → empty roles (same as empty).
	roles, err := parseMongoRoles("   ")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// ──────────────────────────── connectRedis error path ─────────────────────

func TestConnectRedis_InvalidURI(t *testing.T) {
	_, err := connectRedis(context.Background(), "not-a-redis-uri://whatever")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis admin URI")
}

func TestConnectRedis_UnreachableHost(t *testing.T) {
	_, err := connectRedis(context.Background(), "redis://:pass@localhost:19999/0")
	require.Error(t, err)
}

// ──────────────────────────── connectMongo error path ─────────────────────

func TestConnectMongo_UnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, "mongodb://admin:pass@localhost:27099/")
	require.Error(t, err)
}

// ──────────────────────────── openMySQL error path ─────────────────────────

func TestOpenMySQL_ValidDSNButUnreachable(t *testing.T) {
	// A valid DSN format but non-existent host → PingContext fails.
	_, err := openMySQL(context.Background(), "user:pass@tcp(localhost:13306)/db", false)
	require.Error(t, err)
}

// ──────────────────────────── mysqlAccountRef ──────────────────────────────

func TestMysqlAccountRef_Format(t *testing.T) {
	ref := mysqlAccountRef("kx_dyn_test123")
	assert.Equal(t, "'kx_dyn_test123'@'%'", ref)
}

// ──────────────────────────── randString edge ──────────────────────────────

func TestRandString_ZeroLength(t *testing.T) {
	s, err := randString(0)
	require.NoError(t, err)
	assert.Equal(t, "", s)
}

// ──────────────────────────── MongoEngine Issue with valid roles ───────────

func TestMongoEngine_Issue_ValidRolesUnreachable(t *testing.T) {
	e := &MongoEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Valid roles JSON but unreachable MongoDB → should fail at connectMongo.
	_, _, err := e.Issue(ctx, "mongodb://admin:pass@localhost:27099/admin", `{"roles": ["readWrite"]}`, time.Minute)
	require.Error(t, err)
}

// ──────────────────────────── MongoEngine Revoke connect error ──────────────

func TestMongoEngine_Revoke_ConnectError(t *testing.T) {
	e := &MongoEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := e.Revoke(ctx, "mongodb://admin:pass@localhost:27099/", "kx_dyn_validname")
	require.Error(t, err)
}

// ──────────────────────────── Redis Issue unreachable ──────────────────────

func TestRedisEngine_Issue_UnreachableHost(t *testing.T) {
	e := &RedisEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, "redis://:pass@localhost:19999/0", "~app:* +@read", time.Minute)
	require.Error(t, err)
}

// ──────────────────────────── Redis Revoke connect error ───────────────────

func TestRedisEngine_Revoke_ConnectError(t *testing.T) {
	e := &RedisEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := e.Revoke(ctx, "redis://:pass@localhost:19999/0", "kx_dyn_test")
	require.Error(t, err)
}

// ──────────────────────────── parseRedisACLRules ───────────────────────────

func TestParseRedisACLRules_EmptyTemplate(t *testing.T) {
	rules := parseRedisACLRules("")
	assert.Empty(t, rules)
}

func TestParseRedisACLRules_WithRules(t *testing.T) {
	rules := parseRedisACLRules("~app:* +@read +@write")
	assert.Len(t, rules, 3)
	assert.Equal(t, "~app:*", rules[0])
}

// ──────────────────────────── parseMongoRoles extras ──────────────────────

func TestParseMongoRoles_ValidRoles(t *testing.T) {
	roles, err := parseMongoRoles(`{"roles": ["readWrite", {"role": "clusterMonitor", "db": "admin"}]}`)
	require.NoError(t, err)
	assert.Len(t, roles, 2)
}

func TestParseMongoRoles_MissingRolesKey(t *testing.T) {
	_, err := parseMongoRoles(`{"permissions": ["read"]}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles")
}

// ──────────────────────────── MySQL Issue/Revoke extras ───────────────────

func TestMySQLEngine_Revoke_ValidDSNUnreachable(t *testing.T) {
	e := &MySQLEngine{}
	// A well-formed DSN but non-existent host → openMySQL fails after assertSafeUsername passes.
	err := e.Revoke(context.Background(), "user:pass@tcp(localhost:13306)/db", "kx_dyn_abc")
	require.Error(t, err)
}

func TestMySQLEngine_Issue_ValidDSNUnreachable(t *testing.T) {
	e := &MySQLEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, "user:pass@tcp(localhost:13306)/db", "GRANT SELECT ON `app`.* TO ?@?", time.Minute)
	// Expected: failure at openMySQL, not a panic.
	_ = err
}

// ──────────────────────────── AWSSTSEngine extras ─────────────────────────

func TestAWSSTSEngine_RevokeInvalidatesCredential(t *testing.T) {
	e := &AWSSTSEngine{}
	assert.False(t, e.RevokeInvalidatesCredential(""), "STS sessions cannot be revoked per the file header")
}

func TestAWSSTSEngine_Revoke_Noop(t *testing.T) {
	e := &AWSSTSEngine{}
	require.NoError(t, e.Revoke(context.Background(), "", "sessionname"))
}

func TestAWSSTSEngine_Renew_Error(t *testing.T) {
	e := &AWSSTSEngine{}
	err := e.Renew(context.Background(), "", "sessionname", time.Now().Add(time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "renewable")
}

func TestAWSSTSEngine_Issue_MissingRoleARN(t *testing.T) {
	e := &AWSSTSEngine{}
	_, _, err := e.Issue(context.Background(), `{"region":"us-east-1"}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role_arn")
}

func TestAWSSTSEngine_Issue_NotJSON(t *testing.T) {
	e := &AWSSTSEngine{}
	_, _, err := e.Issue(context.Background(), "not-json", "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON")
}

// Verify the error message format for unsafe usernames in each engine.
func TestRedisEngine_Revoke_UnsafeRole_ErrorMessage(t *testing.T) {
	e := &RedisEngine{}
	err := e.Revoke(context.Background(), "redis://:p@h:6379/0", "evil'name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("refusing unsafe dynamic-secret username %q", "evil'name"))
}

func TestMongoEngine_Revoke_UnsafeRole_ErrorMessage(t *testing.T) {
	e := &MongoEngine{}
	err := e.Revoke(context.Background(), "mongodb://admin:p@h:27017/", "evil'; drop")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}
