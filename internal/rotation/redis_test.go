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
}
