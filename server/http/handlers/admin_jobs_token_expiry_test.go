// admin_jobs_token_expiry_test.go — handler-level tests for RunTokenExpiryCheck.
package handlers

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newTokenExpiryJobsHandler creates an AdminJobsHandler whose core is migrated
// with the models CheckTokenExpiry needs.
func newTokenExpiryJobsHandler(t *testing.T) *AdminJobsHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.Notification{}, &models.RolePermission{}, &models.Permission{},
		&models.PersonalAccessToken{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
	))
	return NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

// TestRunTokenExpiryCheck_HappyPath verifies the handler returns 200 with all-zero
// counters when there are no expiring tokens.
func TestRunTokenExpiryCheck_HappyPath(t *testing.T) {
	h := newTokenExpiryJobsHandler(t)
	w := postJob(h.RunTokenExpiryCheck, "/api/v1/admin/jobs/token-expiry-check", true)
	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.EqualValues(t, 0, d["pat_warnings"])
	assert.EqualValues(t, 0, d["pat_criticals"])
	assert.EqualValues(t, 0, d["machine_warnings"])
	assert.EqualValues(t, 0, d["machine_criticals"])
}

// TestRunTokenExpiryCheck_NoUserContext verifies the handler returns 401 when
// no user is in the request context.
func TestRunTokenExpiryCheck_NoUserContext(t *testing.T) {
	h := newTokenExpiryJobsHandler(t)
	w := postJob(h.RunTokenExpiryCheck, "/api/v1/admin/jobs/token-expiry-check", false)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRunTokenExpiryCheck_StorageError verifies the handler returns 500 when the
// underlying storage returns an error (closed DB).
func TestRunTokenExpiryCheck_StorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.MachineIdentityCredential{}))

	h := NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	// Close the underlying DB to force a storage error on ListExpiringPATs.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	w := postJob(h.RunTokenExpiryCheck, "/api/v1/admin/jobs/token-expiry-check", true)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
