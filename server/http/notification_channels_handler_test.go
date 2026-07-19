// notification_channels_handler_test.go — handler-level integration tests for
// the notification channel CRUD endpoints (feat/notification-channels).
// All routes live under /api/v1/notification-channels and are gated on
// system.write (admin only).
package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newNotificationChannelCore replicates newTestCore's full AutoMigrate list and
// also migrates &models.NotificationChannel{} so the notification-channel
// handler tests have a database that matches the real production schema.
func newNotificationChannelCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	err = db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.ShareRecord{},
		&models.AuditEvent{},
		&models.Session{},
		&models.Project{},
		&models.Environment{},
		&models.Permission{},
		&models.RolePermission{},
		&models.SystemMetadata{},
		&models.LoginAttempt{},
		&models.PasswordHistory{},
		&models.PersonalAccessToken{},
		&models.Tag{},
		&models.SecretTag{},
		&models.ProjectInvitation{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.Notification{},
		&models.SetupToken{},
		&models.ProjectMembership{},
		&models.MFASecret{},
		&models.MFARecoveryCode{},
		&models.MFAChallenge{},
		&models.SecretDependency{},
		&models.MachineIdentity{},
		&models.MachineIdentityCredential{},
		&models.MachineIdentityRole{},
		&models.MachineIdentityOIDCBinding{},
		&models.WebAuthnCredential{},
		&models.WebAuthnSession{},
		&models.LegalHold{},
		&models.AccessReviewCampaign{},
		&models.AccessReviewItem{},
		&models.BreakGlassActivation{},
		&models.RiskException{},
		&models.SoDPolicy{},
		&models.ConnectRefGrant{},
		&models.AnomalyAlert{},
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.SSOLoginState{},
		&models.SchedulerLockLease{},
		&models.SecretACL{},
		&models.AnomalyConfigRecord{},
		&models.NotificationChannel{},
		&models.StatsSnapshot{},
		&models.DeploymentStatsSnapshot{},
	)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// notificationChannelTestSetup is a convenience helper that initialises i18n,
// builds a core, mints an admin token, and starts a real httptest.Server. It
// returns the server and the admin bearer token. Cleanup is registered with t.
func notificationChannelTestSetup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newNotificationChannelCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, token
}

// TestNotificationChannelList_Empty verifies that an admin GET on the list
// endpoint returns 200 with a "data" field that wraps an empty channels array.
func TestNotificationChannelList_Empty(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body, "data")

	// The handler wraps the list as {"channels": [...]} inside "data".
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "data must be an object")
	channels, ok := data["channels"].([]interface{})
	require.True(t, ok, "data.channels must be an array")
	assert.Empty(t, channels)
}

// TestNotificationChannelCreate_Webhook verifies that POSTing a valid webhook
// channel returns 201 with the created record in response data (including an id).
func TestNotificationChannelCreate_Webhook(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload := map[string]interface{}{
		"name":   "ops-hook",
		"type":   "webhook",
		"url":    "https://hook.example.com",
		"events": "anomaly.detected",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var respBody map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	data, ok := respBody["data"].(map[string]interface{})
	require.True(t, ok, "data must be an object")
	assert.NotNil(t, data["id"], "created channel must have an id")
	assert.Equal(t, "ops-hook", data["name"])
	assert.Equal(t, "webhook", data["type"])
	assert.Equal(t, "https://hook.example.com", data["url"])
	assert.Equal(t, "anomaly.detected", data["events"])
}

// TestNotificationChannelCreate_InvalidType verifies that POSTing a channel
// with an unsupported type returns 400.
func TestNotificationChannelCreate_InvalidType(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload := map[string]interface{}{
		"name": "fax-channel",
		"type": "fax",
		"url":  "https://fax.example.com",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelCreate_WebhookMissingURL verifies that creating a
// webhook channel without a URL returns 400.
func TestNotificationChannelCreate_WebhookMissingURL(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload := map[string]interface{}{
		"name": "no-url-hook",
		"type": "webhook",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelDelete verifies the delete-then-get-404 flow:
// create a channel, DELETE it (→ 200), then GET it (→ 404).
func TestNotificationChannelDelete(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	// Create a channel to delete.
	createPayload, err := json.Marshal(map[string]interface{}{
		"name":   "to-delete",
		"type":   "webhook",
		"url":    "https://delete.example.com",
		"events": "secret.rotated",
	})
	require.NoError(t, err)

	createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(createPayload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var createBody map[string]interface{}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	data, ok := createBody["data"].(map[string]interface{})
	require.True(t, ok)
	// id comes back as a JSON number (float64 when decoded into interface{}).
	idFloat, ok := data["id"].(float64)
	require.True(t, ok, "id must be a number")
	id := int(idFloat)

	// DELETE the channel.
	delReq, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/notification-channels/"+itoa(id), nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)

	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	defer delResp.Body.Close()
	assert.Equal(t, http.StatusOK, delResp.StatusCode)

	// GET must now return 404.
	getReq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels/"+itoa(id), nil)
	require.NoError(t, err)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// TestNotificationChannels_Unauthenticated verifies that the list endpoint
// returns 401 when no Authorization header is present.
func TestNotificationChannels_Unauthenticated(t *testing.T) {
	srv, _ := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels", nil)
	require.NoError(t, err)
	// Deliberately omit the Authorization header.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// itoa converts an int to its decimal string representation. Used to build URL
// path segments without importing strconv or fmt in every test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
