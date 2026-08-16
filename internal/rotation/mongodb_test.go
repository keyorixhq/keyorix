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
	// #132 sibling gap: postgres.go/mysql.go redact a driver error that echoes a live
	// credential before wrapping it; that redaction was never applied to mongodb.go,
	// reopening the same leak class for a backend whose admin credential lives in the
	// DSN/URI itself rather than in a SQL statement.
	t.Run("backend error echoing a URI-shaped credential is redacted", func(t *testing.T) {
		fake := &fakeMongo{err: errors.New(`dial failed: mongodb://admin:S3cr3t-Live-Value!@db:27017: connection refused`)}
		err := mongoWith(fake, "app_").Rotate(context.Background(), "app_svc", "v")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "S3cr3t-Live-Value!", "the live credential must never appear in the returned error")
		assert.Contains(t, err.Error(), "app_svc", "the ref is still useful diagnostic context")
		assert.Contains(t, err.Error(), "***@", "the redacted userinfo is replaced with a placeholder, not silently dropped")
	})
}

// TestMongo_ConnErrorRedactsURICredentialIfEchoed exercises mongodb.go's conn()-error
// path via a fake newConn that simulates a URI-shaped connect failure. MongoDB's
// connstring parser was checked empirically (options.Client().ApplyURI + Validate against
// several malformed-DSN shapes) and does not echo the raw URI on any case exercised, but
// conn()'s error is still redacted for defense in depth — this confirms that redaction is
// actually wired up on the connect path too, not only the mutate path, so a future
// connstring/driver change can't silently reopen this.
func TestMongo_ConnErrorRedactsURICredentialIfEchoed(t *testing.T) {
	e := NewMongoExecutor("mongo", "mongodb://admin:pw@db:27017", []string{"app_"})
	e.newConn = func(context.Context, string) (mongoConn, error) {
		return nil, errors.New(`dial failed: mongodb://admin:S3cr3t-Live-Value!@db:27017: connection refused`)
	}
	err := e.Rotate(context.Background(), "app_svc", "v")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "S3cr3t-Live-Value!", "the live credential must never appear in the returned error")
	assert.Contains(t, err.Error(), "app_svc", "the ref is still useful diagnostic context")
}
