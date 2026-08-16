package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRedis struct {
	gotUser, gotPass string
	called           bool
	err              error
}

func (f *fakeRedis) SetUserPassword(_ context.Context, user, pass string) error {
	f.called = true
	f.gotUser, f.gotPass = user, pass
	return f.err
}
func (f *fakeRedis) Close() error { return nil }

func redisWith(fake *fakeRedis, allowed ...string) *RedisExecutor {
	e := NewRedisExecutor("redis", "redis://default:pw@db:6379/0", allowed)
	e.newConn = func(context.Context, string) (redisConn, error) { return fake, nil }
	return e
}

func TestRedis_TypeAndName(t *testing.T) {
	e := NewRedisExecutor("prod-redis", "dsn", nil)
	assert.Equal(t, "prod-redis", e.Name())
	assert.Equal(t, "redis", e.Type())
}

func TestRedis_RotatePassesUserAndPassword(t *testing.T) {
	fake := &fakeRedis{}
	require.NoError(t, redisWith(fake, "svc-").Rotate(context.Background(), "svc-app", "n3w"))
	assert.True(t, fake.called)
	assert.Equal(t, "svc-app", fake.gotUser)
	assert.Equal(t, "n3w", fake.gotPass)
}

func TestRedis_RotateErrors(t *testing.T) {
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		fake := &fakeRedis{}
		err := redisWith(fake).Rotate(context.Background(), "any", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
		assert.False(t, fake.called)
	})
	t.Run("guardrail", func(t *testing.T) {
		fake := &fakeRedis{}
		err := redisWith(fake, "svc-").Rotate(context.Background(), "root", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.False(t, fake.called)
	})
	t.Run("backend error", func(t *testing.T) {
		fake := &fakeRedis{err: errors.New("NOPERM")}
		err := redisWith(fake, "svc-").Rotate(context.Background(), "svc-app", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NOPERM")
	})
	// #132 sibling gap: postgres.go/mysql.go redact a driver error that echoes a live
	// credential before wrapping it; that redaction was never applied to redis.go,
	// reopening the same leak class for a backend whose admin credential lives in the
	// DSN/URI itself rather than in a SQL statement.
	t.Run("backend error echoing a URI-shaped credential is redacted", func(t *testing.T) {
		fake := &fakeRedis{err: errors.New(`dial failed: redis://default:S3cr3t-Live-Value!@db:6379: connection refused`)}
		err := redisWith(fake, "svc-").Rotate(context.Background(), "svc-app", "v")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "S3cr3t-Live-Value!", "the live credential must never appear in the returned error")
		assert.Contains(t, err.Error(), "svc-app", "the ref is still useful diagnostic context")
		assert.Contains(t, err.Error(), "***@", "the redacted userinfo is replaced with a placeholder, not silently dropped")
	})
}

// TestRedis_ConnErrorRedactsDSNCredential exercises the REAL redis.ParseURL path (no
// newConn override): go-redis parses the admin DSN with the stdlib net/url package, and
// net/url's *url.Error stringifies as `parse %q: %s` with the ORIGINAL raw input on a
// parse failure — credentials and all (net/url only redacts userinfo when a caller
// explicitly calls URL.Redacted(), which ParseURL never does; confirmed empirically
// against github.com/redis/go-redis/v9). A malformed admin DSN — as mundane as a typo'd
// port — must not leak the live admin password into the returned error.
func TestRedis_ConnErrorRedactsDSNCredential(t *testing.T) {
	e := NewRedisExecutor("redis", "redis://admin:S3cr3t-Live-Value!@127.0.0.1:notaport/0", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "newpw")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "S3cr3t-Live-Value!", "the admin DSN credential must never appear in the returned error")
	assert.Contains(t, err.Error(), "svc-app", "the ref is still useful diagnostic context")
}
