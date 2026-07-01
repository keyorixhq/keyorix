package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMySQL struct {
	query  string
	called bool
	err    error
}

func (f *fakeMySQL) Exec(_ context.Context, q string) error {
	f.called = true
	f.query = q
	return f.err
}
func (f *fakeMySQL) Close() error { return nil }

func myWith(fake *fakeMySQL, allowed ...string) *MySQLExecutor {
	e := NewMySQLExecutor("my", "user:pw@tcp(db:3306)/", allowed)
	e.newConn = func(context.Context, string) (mysqlConn, error) { return fake, nil }
	return e
}

func TestMySQL_TypeAndName(t *testing.T) {
	e := NewMySQLExecutor("prod-my", "dsn", nil)
	assert.Equal(t, "prod-my", e.Name())
	assert.Equal(t, "mysql", e.Type())
}

func TestMySQL_RotateBuildsAlterUser(t *testing.T) {
	fake := &fakeMySQL{}
	// bare user → default host '%'
	require.NoError(t, myWith(fake, "app_").Rotate(context.Background(), "app_svc", "n3wp4ss"))
	assert.True(t, fake.called)
	assert.Equal(t, `ALTER USER 'app_svc'@'%' IDENTIFIED BY 'n3wp4ss'`, fake.query)
}

func TestMySQL_RotateWithExplicitHost(t *testing.T) {
	fake := &fakeMySQL{}
	require.NoError(t, myWith(fake, "app_").Rotate(context.Background(), "app_svc@10.0.0.5", "pw"))
	assert.Equal(t, `ALTER USER 'app_svc'@'10.0.0.5' IDENTIFIED BY 'pw'`, fake.query)
}

// A crafted account/password cannot break out: internal quotes and backslashes doubled.
func TestMySQL_RotateEscapesInjection(t *testing.T) {
	fake := &fakeMySQL{}
	require.NoError(t, myWith(fake, "ro").Rotate(context.Background(), `ro'le`, `pa\'ss`))
	assert.Equal(t, `ALTER USER 'ro''le'@'%' IDENTIFIED BY 'pa\\''ss'`, fake.query)
}

func TestMySQL_RotateFailsClosedWithoutAllowedRefs(t *testing.T) {
	fake := &fakeMySQL{}
	err := myWith(fake).Rotate(context.Background(), "any", "v") // no allowed_refs
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no allowed_refs")
	assert.False(t, fake.called)
}

func TestMySQL_RotateErrors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		fake := &fakeMySQL{}
		require.Error(t, myWith(fake, "x").Rotate(context.Background(), "", "v"))
		assert.False(t, fake.called)
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeMySQL{}
		err := myWith(fake, "app_").Rotate(context.Background(), "root", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.False(t, fake.called)
	})
	t.Run("backend error propagates", func(t *testing.T) {
		fake := &fakeMySQL{err: errors.New("access denied")}
		err := myWith(fake, "app_").Rotate(context.Background(), "app_svc", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access denied")
	})
	// #132: mirrors the postgres redaction test — a driver error echoing the
	// failing statement must not leak the new password literal.
	t.Run("backend error echoing the statement is redacted", func(t *testing.T) {
		fake := &fakeMySQL{err: errors.New(`Error 1064: syntax error near 'S3cr3t-Live-Value!'`)}
		err := myWith(fake, "app_").Rotate(context.Background(), "app_svc", "S3cr3t-Live-Value!")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "S3cr3t-Live-Value!", "the live credential must never appear in the returned error")
		assert.Contains(t, err.Error(), "app_svc")
	})
}
