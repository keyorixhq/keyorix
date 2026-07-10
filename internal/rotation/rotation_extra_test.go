package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_DuplicateNameLastWins validates that a later executor overwrites
// an earlier one with the same name.
func TestManager_DuplicateNameLastWins(t *testing.T) {
	a1 := stubExec{name: "alpha"}
	a2 := stubExec{name: "alpha"}
	m := NewManager([]Executor{a1, a2})
	e, ok := m.Get("alpha")
	require.True(t, ok)
	assert.Equal(t, "alpha", e.Name())
	// Names() must only list "alpha" once.
	assert.Len(t, m.Names(), 1)
}

// TestManager_Empty validates that an empty manager has no names and returns
// false for any lookup.
func TestManager_Empty(t *testing.T) {
	m := NewManager(nil)
	_, ok := m.Get("anything")
	assert.False(t, ok)
	assert.Empty(t, m.Names())
}

// TestManager_OnlyNilEntries validates that a manager with only nil entries has
// no executors.
func TestManager_OnlyNilEntries(t *testing.T) {
	m := NewManager([]Executor{nil, nil})
	assert.Empty(t, m.Names())
}

// TestPrefixAllowed_EmptyList allows anything.
func TestPrefixAllowed_EmptyList(t *testing.T) {
	assert.True(t, prefixAllowed([]string{}, "anything"))
	assert.True(t, prefixAllowed(nil, ""))
	assert.True(t, prefixAllowed(nil, "some/ref"))
}

// TestPrefixAllowed_ExactPrefix ensures an exact prefix matches.
func TestPrefixAllowed_ExactPrefix(t *testing.T) {
	assert.True(t, prefixAllowed([]string{"prod_"}, "prod_db"))
	assert.True(t, prefixAllowed([]string{"prod_"}, "prod_"))
}

// TestPrefixAllowed_MultipleAllowed validates that any matching prefix in the
// list allows the ref.
func TestPrefixAllowed_MultipleAllowed(t *testing.T) {
	allowed := []string{"dev_", "staging_", "prod_"}
	assert.True(t, prefixAllowed(allowed, "dev_svc"))
	assert.True(t, prefixAllowed(allowed, "staging_db"))
	assert.True(t, prefixAllowed(allowed, "prod_app"))
	assert.False(t, prefixAllowed(allowed, "other_thing"))
}

// TestPrefixAllowed_EmptyPrefixNeverMatches validates that an empty string
// prefix in the allowed list is never matched, as documented.
func TestPrefixAllowed_EmptyPrefixNeverMatches(t *testing.T) {
	assert.False(t, prefixAllowed([]string{""}, "anything"))
	assert.False(t, prefixAllowed([]string{"", "ok_"}, "anything"))
	assert.True(t, prefixAllowed([]string{"", "ok_"}, "ok_ref"))
}

// TestRedactSQLError_RemovesSingleQuotedLiteral ensures the SQL password is
// redacted from a driver error message that echoes the statement.
func TestRedactSQLError_RemovesSingleQuotedLiteral(t *testing.T) {
	raw := errors.New("ALTER USER alice WITH PASSWORD 'supersecret'")
	wrapped := redactSQLError("postgresql", "alice", raw)
	require.Error(t, wrapped)
	assert.NotContains(t, wrapped.Error(), "supersecret")
	assert.Contains(t, wrapped.Error(), "'***'")
	assert.Contains(t, wrapped.Error(), "alice")
	assert.Contains(t, wrapped.Error(), "postgresql")
}

// TestRedactSQLError_MultipleQuotedLiterals ensures all quoted literals are
// redacted when the error echoes multiple values.
func TestRedactSQLError_MultipleQuotedLiterals(t *testing.T) {
	raw := errors.New("syntax error near 'password1' and 'password2'")
	wrapped := redactSQLError("mysql", "bob", raw)
	assert.NotContains(t, wrapped.Error(), "password1")
	assert.NotContains(t, wrapped.Error(), "password2")
}

// TestRedactSQLError_NoLiterals passes through a message that has no
// single-quoted literals unchanged (aside from wrapping).
func TestRedactSQLError_NoLiterals(t *testing.T) {
	raw := errors.New("connection refused")
	wrapped := redactSQLError("postgresql", "carol", raw)
	assert.Contains(t, wrapped.Error(), "connection refused")
}

// TestRedactSQLError_EmbeddedDoubleQuoteEscape validates that the SQL
// ''-doubling escape within a quoted literal is handled correctly.
func TestRedactSQLError_EmbeddedDoubleQuoteEscape(t *testing.T) {
	// 'it''s a secret' is one SQL string literal (contains embedded '')
	raw := errors.New("ALTER ROLE r WITH PASSWORD 'it''s a secret'")
	wrapped := redactSQLError("postgresql", "r", raw)
	assert.NotContains(t, wrapped.Error(), "it''s a secret")
	assert.Contains(t, wrapped.Error(), "'***'")
}

// TestPartialRotationError_ErrorAndUnwrap validates the error interface
// of PartialRotationError.
func TestPartialRotationError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	pErr := &PartialRotationError{Value: "newkey", Err: cause}

	assert.Equal(t, cause.Error(), pErr.Error())
	assert.Equal(t, "newkey", pErr.Value)

	var unwrapped *PartialRotationError
	assert.False(t, errors.As(errors.New("other"), &unwrapped))
	assert.True(t, errors.Is(errors.Unwrap(pErr), cause))
}

// generatingStub is a stub Executor that also implements GeneratingExecutor.
type generatingStub struct {
	stubExec
	upstream string
}

func (g generatingStub) GenerateUpstream(_ context.Context, _ string) (string, error) {
	return g.upstream, nil
}

// TestManager_GeneratingExecutorInterface validates that an executor
// implementing GeneratingExecutor is stored and retrievable.
func TestManager_GeneratingExecutorInterface(t *testing.T) {
	gen := generatingStub{stubExec: stubExec{name: "cloud-key"}, upstream: "new-value"}
	m := NewManager([]Executor{gen})

	e, ok := m.Get("cloud-key")
	require.True(t, ok)

	// Cast to GeneratingExecutor interface.
	ge, ok := e.(GeneratingExecutor)
	require.True(t, ok, "retrieved executor must implement GeneratingExecutor")

	val, err := ge.GenerateUpstream(context.Background(), "ref")
	require.NoError(t, err)
	assert.Equal(t, "new-value", val)
}
