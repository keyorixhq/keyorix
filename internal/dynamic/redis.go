package dynamic

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisEngine mints short-lived Redis ACL users on the target and drops them on
// revoke. Like MySQL and MongoDB (and unlike PostgreSQL's VALID UNTIL), Redis ACL
// users carry no built-in expiry, so a lease's TTL is enforced solely by the
// dynamic-secrets auto-revoke sweeper (ADR-035) — the sweeper must be enabled for
// Redis credentials to expire; the `ACL DELUSER` at revoke is the authoritative
// teardown either way.
//
// adminDSN is a Redis connection URI ("redis://:adminpass@host:6379/0", or
// "rediss://…" for TLS) for a user that holds the `+acl` command. The creation
// template is operator-authored ACL rule tokens applied to the new user, e.g.
//
//	~app:* +@read +@write
//	allkeys +@all
//
// The generated username and password are passed to `ACL SETUSER` as DISCRETE
// command arguments (RESP bulk strings), never string-interpolated, so the
// credential can never be parsed as an ACL token — injection is structurally
// impossible. The ACL rule tokens are the operator-authored trust boundary (the
// analogue of the SQL creation_template / Mongo role spec).
type RedisEngine struct{}

func (e *RedisEngine) BackendType() string      { return "redis" }
func (e *RedisEngine) IsEphemeralBackend() bool { return false }

// RevokeInvalidatesCredential is always true: ACL DELUSER really removes the
// account, so a subsequent auth attempt with it fails immediately.
func (e *RedisEngine) RevokeInvalidatesCredential(_ string) bool { return true }

// SupportsNativeExpiry is false: Redis ACL users have no native expiry, so lease
// expiry is enforced only by the auto-revoke sweeper (which must be enabled).
func (e *RedisEngine) SupportsNativeExpiry() bool { return false }

// redisOpTimeout bounds connect/ping and each ACL command at issue/revoke time.
const redisOpTimeout = 10 * time.Second

func (e *RedisEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, _ time.Duration) (Credential, string, error) {
	rules := parseRedisACLRules(creationTemplate)

	client, err := connectRedis(ctx, adminDSN)
	if err != nil {
		return Credential{}, "", err
	}
	defer func() { _ = client.Close() }()

	suffix, err := randString(16)
	if err != nil {
		return Credential{}, "", err
	}
	user := "kx_dyn_" + suffix
	password, err := randString(32)
	if err != nil {
		return Credential{}, "", err
	}

	opCtx, cancel := context.WithTimeout(ctx, redisOpTimeout)
	defer cancel()

	// ACL SETUSER <user> on >password <rules...>. Each element is a discrete arg —
	// the generated username/password are typed bulk strings, never concatenated
	// into a command, so they cannot break out into ACL tokens.
	args := make([]interface{}, 0, len(rules)+5)
	args = append(args, "ACL", "SETUSER", user, "on", ">"+password)
	for _, r := range rules {
		args = append(args, r)
	}
	if err := client.Do(opCtx, args...).Err(); err != nil {
		return Credential{}, "", fmt.Errorf("create acl user: %w", err)
	}
	return Credential{Username: user, Password: password}, user, nil
}

// Revoke deletes the ACL user. roleName is the bare username.
func (e *RedisEngine) Revoke(ctx context.Context, adminDSN, roleName string) error {
	// Defense-in-depth: reject a tampered role name before any connection. (Redis
	// passes it as a discrete arg, so this is belt-and-suspenders, not the primary
	// injection guard — mirrors the SQL/Mongo engines.)
	if err := assertSafeUsername(roleName); err != nil {
		return err
	}
	client, err := connectRedis(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	opCtx, cancel := context.WithTimeout(ctx, redisOpTimeout)
	defer cancel()
	// ACL DELUSER returns the count removed (0 if absent), so revoke is idempotent.
	if err := client.Do(opCtx, "ACL", "DELUSER", roleName).Err(); err != nil {
		return fmt.Errorf("delete acl user %s: %w", roleName, err)
	}
	return nil
}

// Renew is a no-op for Redis: ACL users carry no expiry, so the renewed lease
// expiry is enforced entirely by the auto-revoke sweep (as with MySQL/MongoDB).
func (e *RedisEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

// parseRedisACLRules splits an operator's ACL creation template into the
// whitespace-separated rule tokens passed to ACL SETUSER (e.g. "~app:* +@read").
// An empty template yields no rules — a user that can authenticate but has no key
// or command permissions (almost always you want rules; this mirrors the Mongo
// empty-roles behaviour).
func parseRedisACLRules(template string) []string {
	return strings.Fields(template)
}

// connectRedis opens and verifies a connection to the target using the admin URI.
func connectRedis(ctx context.Context, adminDSN string) (*redis.Client, error) {
	opts, err := redis.ParseURL(adminDSN)
	if err != nil {
		return nil, fmt.Errorf("invalid redis admin URI: %w", err)
	}
	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, redisOpTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	return client, nil
}
