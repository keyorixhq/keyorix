package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestAuditExportRequiresSystemRead is the sibling of
// TestListAnomalyAlertsRequiresSystemRead (ANOMALY-04) for #2733's bug
// class, found during FIX-1's sweep: GET /api/v1/audit/export and
// /api/v1/audit/export.csv return AuditExportEntry's full-fidelity shape
// (IPAddress, tamper-evidence hash chain) -- fields /logs and /search
// deliberately redact -- but were registered with only the group's
// audit.read gate, no elevation. A handler-file doc comment already
// asserted a stronger gate existed ("not reachable merely by holding
// audit.read"); it wasn't, until this fix. Raised to audit.read AND
// system.read, matching /anomalies' already-tested bar exactly.
func TestAuditExportRequiresSystemRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "operator", Email: "op@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", Email: "v@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	// "operator" holds system.read (and audit.read); "viewer" holds only audit.read.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "operator"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "audit.read", Resource: "audit", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "system.read", Resource: "system", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "operator-tok")
	seedSession(t, db, 2, "viewer-tok")

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(token, path string) int {
		req, err := http.NewRequest("GET", server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	for _, path := range []string{"/api/v1/audit/export", "/api/v1/audit/export.csv"} {
		assert.Equal(t, http.StatusForbidden, get("viewer-tok", path),
			"audit.read holder without system.read must be forbidden from %s (IPAddress exposure)", path)
		assert.NotEqual(t, http.StatusForbidden, get("operator-tok", path),
			"system.read holder should be allowed to reach %s", path)
	}
}
