package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePG struct {
	sql    string
	called bool
	err    error
}

func (f *fakePG) Exec(_ context.Context, sql string) error {
	f.called = true
	f.sql = sql
	return f.err
}
func (f *fakePG) Close(context.Context) {}

func pgWith(fake *fakePG, allowed ...string) *PostgresExecutor {
	e := NewPostgresExecutor("pg", "postgres://admin@db/postgres", allowed)
	e.newConn = func(context.Context, string) (pgConn, error) { return fake, nil }
	return e
}

func TestPostgres_TypeAndName(t *testing.T) {
	e := NewPostgresExecutor("prod-pg", "dsn", nil)
	assert.Equal(t, "prod-pg", e.Name())
	assert.Equal(t, "postgresql", e.Type())
}

func TestPostgres_RotateBuildsAlterRole(t *testing.T) {
	fake := &fakePG{}
	require.NoError(t, pgWith(fake).Rotate(context.Background(), "app_svc", "n3wp4ss"))
	assert.True(t, fake.called)
	assert.Equal(t, `ALTER ROLE "app_svc" WITH PASSWORD 'n3wp4ss'`, fake.sql)
}

// A crafted role name / password cannot break out of the statement: identifiers double
// internal double-quotes, literals double internal single-quotes.
func TestPostgres_RotateEscapesInjection(t *testing.T) {
	fake := &fakePG{}
	err := pgWith(fake).Rotate(context.Background(), `ro"le`, `pa'ss`)
	require.NoError(t, err)
	assert.Equal(t, `ALTER ROLE "ro""le" WITH PASSWORD 'pa''ss'`, fake.sql)
}

func TestPostgres_RotateErrors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		fake := &fakePG{}
		require.Error(t, pgWith(fake).Rotate(context.Background(), "", "v"))
		assert.False(t, fake.called)
	})
	t.Run("empty value", func(t *testing.T) {
		fake := &fakePG{}
		require.Error(t, pgWith(fake).Rotate(context.Background(), "role", ""))
		assert.False(t, fake.called)
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakePG{}
		e := pgWith(fake, "app_")
		err := e.Rotate(context.Background(), "root", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.False(t, fake.called, "a disallowed ref must not reach the backend")
	})
	t.Run("missing dsn", func(t *testing.T) {
		fake := &fakePG{}
		e := NewPostgresExecutor("pg", "", nil)
		e.newConn = func(context.Context, string) (pgConn, error) { return fake, nil }
		require.Error(t, e.Rotate(context.Background(), "role", "v"))
		assert.False(t, fake.called)
	})
	t.Run("backend error propagates", func(t *testing.T) {
		fake := &fakePG{err: errors.New("permission denied for role")}
		err := pgWith(fake).Rotate(context.Background(), "role", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
	})
}
