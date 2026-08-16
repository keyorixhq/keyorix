// redis.go — the Redis rotation executor (ADR-047). Rotate replaces an ACL user's
// password via `ACL SETUSER <user> resetpass ><newpass>`. The username and password are
// passed as DISCRETE command arguments (never concatenated into a command string), so
// neither can be parsed as an ACL token — injection is structurally impossible.
package rotation

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisOpTimeout = 10 * time.Second

// redisConn is the high-level seam the executor uses — set a user's password and close.
type redisConn interface {
	SetUserPassword(ctx context.Context, user, password string) error
	Close() error
}

// RedisExecutor rotates a Redis ACL user's password (keeping its other ACL rules).
type RedisExecutor struct {
	name        string
	dsn         string
	allowedRefs []string
	newConn     func(ctx context.Context, dsn string) (redisConn, error)
}

// NewRedisExecutor builds a Redis rotation executor. dsn is the admin connection URL
// (redis://… , operator-provided, env-sourced). allowedRefs restricts which ACL
// usernames it may rotate (prefix allowlist) — required (fail-closed).
func NewRedisExecutor(name, dsn string, allowedRefs []string) *RedisExecutor {
	return &RedisExecutor{name: name, dsn: dsn, allowedRefs: allowedRefs}
}

func (e *RedisExecutor) Name() string { return e.name }
func (e *RedisExecutor) Type() string { return "redis" }

func (e *RedisExecutor) conn(ctx context.Context) (redisConn, error) {
	if e.newConn != nil {
		return e.newConn(ctx, e.dsn)
	}
	opt, err := redis.ParseURL(e.dsn)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	return &redisClientConn{client: redis.NewClient(opt)}, nil
}

// Rotate replaces ACL user `ref`'s password with newValue.
func (e *RedisExecutor) Rotate(ctx context.Context, ref, newValue string) error {
	if ref == "" {
		return fmt.Errorf("redis: ACL username (ref) is required")
	}
	if newValue == "" {
		return fmt.Errorf("redis: new value is required")
	}
	if len(e.allowedRefs) == 0 {
		return fmt.Errorf("redis: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return fmt.Errorf("redis: user %q is not permitted by this backend's allowed_refs", ref)
	}
	if e.dsn == "" {
		return fmt.Errorf("redis: backend %q has no admin DSN configured", e.name)
	}
	c, err := e.conn(ctx)
	if err != nil {
		// conn() can fail with a redis.ParseURL error that echoes the admin DSN —
		// credentials and all — verbatim (net/url does not redact on a parse
		// failure). Redact before wrapping so the live admin password never
		// egresses via the rotation-failure SIEM audit / notification broadcast
		// (#132, extended to this backend's DSN-echo leak shape).
		return redactConnError("redis", ref, err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetUserPassword(ctx, ref, newValue); err != nil {
		// Redact before wrapping — see the comment on the conn() error above; kept
		// consistent here even though SetUserPassword's args are discrete (not
		// string-concatenated), matching mysql.go's own defense-in-depth precedent.
		return redactConnError("redis", ref, err)
	}
	return nil
}

// redisClientConn adapts *redis.Client to the redisConn seam.
type redisClientConn struct{ client *redis.Client }

func (r *redisClientConn) SetUserPassword(ctx context.Context, user, password string) error {
	cctx, cancel := context.WithTimeout(ctx, redisOpTimeout)
	defer cancel()
	// resetpass clears existing passwords, then >password adds the new one — the user's
	// other ACL rules/enabled state are preserved. Args are discrete bulk strings.
	return r.client.Do(cctx, "ACL", "SETUSER", user, "resetpass", ">"+password).Err()
}

func (r *redisClientConn) Close() error { return r.client.Close() }
