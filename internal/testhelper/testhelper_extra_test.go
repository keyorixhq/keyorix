// testhelper_extra_test.go — covers the remaining rbac_test_helper.go paths
// left untested by testhelper_s36_test.go: HasPermission's true branch, and
// the Cleanup/ExecuteRawSQL/QueryRawSQL helpers.
package testhelper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHasPermission_TruePath verifies HasPermission returns true when the
// user actually holds the permission via an assigned role, not just the
// false/not-found branch already exercised elsewhere.
func TestHasPermission_TruePath(t *testing.T) {
	h := NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	user := h.CreateTestUser(t, "bob", 101)
	// role ID 4 ("viewer") is seeded with permSecretsRead and permUsersRead.
	h.AssignUserRole(t, user.ID, 4, nil)

	assert.True(t, h.HasPermission(t, user.ID, permSecretsRead),
		"user assigned the viewer role should have secrets.read")
	assert.False(t, h.HasPermission(t, user.ID, permSecretsDelete),
		"viewer role does not grant secrets.delete")
}

// TestExecuteRawSQL_QueryRawSQL verifies ExecuteRawSQL actually mutates the
// database and QueryRawSQL reads back real data (not just that no error is
// returned).
func TestExecuteRawSQL_QueryRawSQL(t *testing.T) {
	h := NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	// name_folded is NOT NULL (#1642); already pure-lowercase ASCII.
	h.ExecuteRawSQL(t, "INSERT INTO roles (id, name, name_folded, description) VALUES (?, ?, ?, ?)",
		999, "raw_sql_role", "raw_sql_role", "created via ExecuteRawSQL")

	rows := h.QueryRawSQL(t, "SELECT name, description FROM roles WHERE id = ?", 999)
	defer rows.Close() //nolint:errcheck

	found := false
	for rows.Next() {
		var name, description string
		require.NoError(t, rows.Scan(&name, &description))
		assert.Equal(t, "raw_sql_role", name)
		assert.Equal(t, "created via ExecuteRawSQL", description)
		found = true
	}
	require.NoError(t, rows.Err())
	assert.True(t, found, "row inserted by ExecuteRawSQL should be visible to QueryRawSQL")
}

// TestCleanup verifies Cleanup actually closes the underlying *sql.DB
// (subsequent use of the connection fails), rather than being a no-op.
func TestCleanup(t *testing.T) {
	h := NewRBACTestHelper(t)

	h.Cleanup()

	err := h.SqlDB.Ping()
	assert.Error(t, err, "SqlDB should be closed after Cleanup")
}

// TestCleanup_NilSqlDB verifies Cleanup tolerates a helper whose SqlDB was
// never set (the nil-guard branch), rather than panicking.
func TestCleanup_NilSqlDB(t *testing.T) {
	h := &RBACTestHelper{}
	assert.NotPanics(t, func() {
		h.Cleanup()
	})
}
