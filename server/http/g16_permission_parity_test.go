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

// g16TestDB builds an in-memory DB migrated with the models the compliance
// posture/digest builder and the secrets/quota-report path touch, plus the
// core RBAC + session tables every router-level authz test needs.
func g16TestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A plain ":memory:" DSN hands a fresh, empty database to every new pooled
	// connection — pin to one connection so every query in this test hits the
	// same DB (matches the pattern in restore_route_authz_test.go).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.RotationPolicy{}, &models.AuditEvent{},
		&models.AnomalyAlert{}, &models.LegalHold{}, &models.SoDPolicy{},
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.AccessRequest{}, &models.RiskException{},
	))
	return db
}

// TestQuotaReportRouteRequiresAuditRead is the G16 regression test: GET
// /api/v1/secrets/quota-report is a report-viewing endpoint (usage %/status
// metadata, never a secret value) — the same disclosure family as the other
// deployment-wide audit reports — so it must require audit.read, not the
// broader secrets.read (which is scoped for actual secret-value access and is
// the wrong tier/shape for a report that discloses no value). A secrets.read
// holder without audit.read must be refused; an audit.read holder must pass.
func TestQuotaReportRouteRequiresAuditRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db := g16TestDB(t)
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "secretreader", Email: "s@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "secretreader"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "audit.read", Resource: "audit", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error) // admin: audit.read
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error) // secretreader: secrets.read ONLY
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "admin-tok")
	seedSession(t, db, 2, "secretreader-tok")

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(token string) int {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/secrets/quota-report", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusForbidden, get("secretreader-tok"),
		"secrets.read holder without audit.read must NOT reach the quota report")
	assert.NotEqual(t, http.StatusForbidden, get("admin-tok"),
		"audit.read holder should be allowed past the gate")
}

// TestComplianceDigestSendRouteRequiresAuditRead is the G16 regression test:
// POST /api/v1/compliance/digest/send restates the SAME posture data as
// GET /api/v1/compliance/digest, so it must require the same audit.read the
// read sibling uses, not the broader system.write. A system.write holder
// without audit.read must be refused; an audit.read holder must pass.
func TestComplianceDigestSendRouteRequiresAuditRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db := g16TestDB(t)
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "sysadmin", Email: "s@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "auditor"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "sysadmin"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "audit.read", Resource: "audit", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error) // auditor: audit.read ONLY
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 2}).Error) // sysadmin: system.write ONLY
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "auditor-tok")
	seedSession(t, db, 2, "sysadmin-tok")

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	post := func(token string) int {
		req, err := http.NewRequest("POST", server.URL+"/api/v1/compliance/digest/send", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusForbidden, post("sysadmin-tok"),
		"system.write holder without audit.read must NOT trigger the compliance digest send")
	assert.NotEqual(t, http.StatusForbidden, post("auditor-tok"),
		"audit.read holder should be allowed past the gate")
}
