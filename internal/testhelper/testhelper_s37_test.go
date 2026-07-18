package testhelper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRBACTestHelper_RawSQL_S37 exercises Cleanup, ExecuteRawSQL, and QueryRawSQL
// — the three functions in rbac_test_helper.go that testhelper_s36_test.go
// does not reach.
func TestRBACTestHelper_RawSQL_S37(t *testing.T) {
	h := NewRBACTestHelper(t)

	// ExecuteRawSQL: runs an arbitrary statement via the raw sql.DB.
	h.ExecuteRawSQL(t, "SELECT 1")

	// QueryRawSQL: returns *sql.Rows; caller must close them.
	rows := h.QueryRawSQL(t, "SELECT 1")
	require.NotNil(t, rows)
	hasRow := rows.Next()
	rows.Close()
	require.True(t, hasRow, "SELECT 1 must return at least one row")

	// Cleanup: closes the underlying *sql.DB.  t.Cleanup will call it again
	// when the test exits; calling it twice is safe (sql.DB.Close is idempotent).
	h.Cleanup()
}
