package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMongo struct {
	gotUser, gotPass string
	called           bool
	err              error
}

func (f *fakeMongo) UpdateUserPassword(_ context.Context, user, pass string) error {
	f.called = true
	f.gotUser, f.gotPass = user, pass
	return f.err
}
func (f *fakeMongo) Close(context.Context) {}

func mongoWith(fake *fakeMongo, allowed ...string) *MongoExecutor {
	e := NewMongoExecutor("mongo", "mongodb://admin:pw@db:27017", allowed)
	e.newConn = func(context.Context, string) (mongoConn, error) { return fake, nil }
	return e
}

func TestMongo_TypeAndName(t *testing.T) {
	e := NewMongoExecutor("prod-mongo", "dsn", nil)
	assert.Equal(t, "prod-mongo", e.Name())
	assert.Equal(t, "mongodb", e.Type())
}

func TestMongo_RotatePassesUserAndPassword(t *testing.T) {
	fake := &fakeMongo{}
	require.NoError(t, mongoWith(fake, "app_").Rotate(context.Background(), "app_svc", "n3w"))
	assert.True(t, fake.called)
	assert.Equal(t, "app_svc", fake.gotUser)
	assert.Equal(t, "n3w", fake.gotPass)
}

func TestMongo_RotateErrors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		fake := &fakeMongo{}
		require.Error(t, mongoWith(fake, "x").Rotate(context.Background(), "", "v"))
		assert.False(t, fake.called)
	})
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		fake := &fakeMongo{}
		err := mongoWith(fake).Rotate(context.Background(), "any", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
		assert.False(t, fake.called)
	})
	t.Run("guardrail", func(t *testing.T) {
		fake := &fakeMongo{}
		err := mongoWith(fake, "app_").Rotate(context.Background(), "root", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.False(t, fake.called)
	})
	t.Run("backend error", func(t *testing.T) {
		fake := &fakeMongo{err: errors.New("UserNotFound")}
		err := mongoWith(fake, "app_").Rotate(context.Background(), "app_svc", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UserNotFound")
	})
}
