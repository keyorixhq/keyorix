// verify_credentials_audit_test.go — regression coverage for the Wave 6
// medium-severity finding (adversarial-review
// findings-handlers/handlers-users-crud.json#2): VerifyCredentials used to
// trust body.IPAddress/body.UserAgent verbatim, writing them straight into
// the audit trail (LogAuthFailure/LogAuthLogin) and the minted session
// record. Those fields come from the JSON request body, not the server's own
// view of the connection, so any caller holding the users.write credential
// this endpoint requires could forge them: inject control characters/
// newlines for audit-log forging, attribute an attempt to an unrelated IP,
// or pad the User-Agent to an unbounded length.
//
// VerifyCredentials is the hub side of a hub/spoke proxy-login mechanism
// (RemoteLoginVerifier — see the handler's doc in users_crud.go): a
// storage.type: remote "spoke" deployment relays the ORIGINAL end user's own
// IP/UA here so the hub's audit trail reflects the real caller, not the
// spoke server's own connection. That's a legitimate reason to accept these
// as body fields at all — but relaying isn't the same as trusting them
// verbatim. The fix (sanitizeProxiedIP / sanitizeProxiedUserAgent in
// users_crud.go) validates the IP as a real address and strips control
// characters + caps the UA length, so a forged value never reaches storage,
// while a legitimate proxied IP/UA still passes through unchanged.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var vcAuditDBCounter atomic.Int64

// freshCoreVCAudit creates a brand-new in-memory SQLite DB with the schema
// VerifyCredentials's full login path needs (users/roles/sessions/audit),
// and returns both the gorm handle (to inspect persisted rows directly) and
// the KeyorixCore built on top of it.
func freshCoreVCAudit(t *testing.T) (*gorm.DB, *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := vcAuditDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_vcaudit_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.LoginAttempt{}, &models.Session{},
		&models.PasswordHistory{}, &models.SystemMetadata{},
	))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	return db, cs
}

// bootstrapVCAuditUser bootstraps a fresh core and returns the created
// user's username/password (a real account VerifyCredentials can log in as).
func bootstrapVCAuditUser(t *testing.T, cs *core.KeyorixCore, suffix string) (username, password string) {
	t.Helper()
	ctx := context.Background()
	token := "vcaudit-" + suffix + "-boot"
	cs.SetBootstrapToken(token)
	username = "vcaudit" + suffix
	password = "Kx#Vr9$Mn2!Zp4@Qw"
	_, err := cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: username,
		Email:    fmt.Sprintf("%s@example.com", username),
		Password: password,
		Token:    token,
	})
	require.NoError(t, err)
	return username, password
}

// latestAuditEvent polls the DB for the most recent audit event of the given
// type, waiting for VerifyCredentials's goSafe-wrapped LogAuthFailure/
// LogAuthLogin goroutine to land (both are deliberately fire-and-forget, so
// the row doesn't necessarily exist the instant the HTTP handler returns).
func latestAuditEvent(t *testing.T, db *gorm.DB, eventType string) *models.AuditEvent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var event models.AuditEvent
		err := db.Where("event_type = ?", eventType).Order("id DESC").First(&event).Error
		if err == nil {
			return &event
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "timed out waiting for a %q audit event", eventType)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestVerifyCredentials_ForgedIPWithNewline_NotStoredVerbatim is the
// regression test for the finding: a caller-supplied ip_address containing
// an embedded newline (a classic audit-log-forging payload — it would render
// as a second, fabricated log line to anything tailing/parsing the audit
// trail) must never reach the persisted audit_events row unsanitized.
func TestVerifyCredentials_ForgedIPWithNewline_NotStoredVerbatim(t *testing.T) {
	db, cs := freshCoreVCAudit(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	const maliciousIP = "203.0.113.9\r\nauth.login_failed FORGED-ENTRY user=root ip=10.0.0.1 success=true"
	body, err := json.Marshal(map[string]string{
		// No such user — this is the LogAuthFailure branch, which is what
		// carries body.IPAddress into the audit trail on a failed attempt.
		"username":   "no-such-vcaudit-user",
		"password":   "wrong-password",
		"ip_address": maliciousIP,
	})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest("POST", "/api/v1/users/verify-credentials", strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	require.Equal(t, 401, w.Code)

	event := latestAuditEvent(t, db, "auth.login_failed")
	assert.NotContains(t, event.IPAddress, "\n", "a forged newline must never reach the persisted audit row")
	assert.NotContains(t, event.IPAddress, "\r")
	assert.NotContains(t, event.IPAddress, "FORGED-ENTRY")
	assert.NotEqual(t, maliciousIP, event.IPAddress, "the malicious body value must not be stored verbatim")
	// The whole string isn't a valid IP address, so it's dropped entirely
	// rather than partially trusted.
	assert.Empty(t, event.IPAddress)
}

// TestVerifyCredentials_LegitimateProxiedIP_StillRecorded proves the fix
// doesn't break the legitimate hub/spoke use case: a syntactically valid IP
// address relayed from a spoke deployment still ends up in the audit trail
// exactly as given.
func TestVerifyCredentials_LegitimateProxiedIP_StillRecorded(t *testing.T) {
	db, cs := freshCoreVCAudit(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	const realIP = "198.51.100.42"
	body, err := json.Marshal(map[string]string{
		"username":   "no-such-vcaudit-user-2",
		"password":   "wrong-password",
		"ip_address": realIP,
	})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest("POST", "/api/v1/users/verify-credentials", strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	require.Equal(t, 401, w.Code)

	event := latestAuditEvent(t, db, "auth.login_failed")
	assert.Equal(t, realIP, event.IPAddress, "a syntactically valid proxied IP must still be recorded")
}

// TestVerifyCredentials_ForgedUserAgent_SanitizedInSession covers the
// success path: a caller-supplied user_agent containing control characters
// (including a NUL byte) and padded far beyond any real browser UA string
// must be cleaned before it's persisted on the minted session record (the
// value the "active sessions" account view later renders back to the user).
func TestVerifyCredentials_ForgedUserAgent_SanitizedInSession(t *testing.T) {
	_, cs := freshCoreVCAudit(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	username, password := bootstrapVCAuditUser(t, cs, "ua")

	maliciousUA := "Evil\x00Agent\x07BEL" + strings.Repeat("A", 2000)
	body, err := json.Marshal(map[string]string{
		"username":   username,
		"password":   password,
		"ip_address": "198.51.100.7",
		"user_agent": maliciousUA,
	})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest("POST", "/api/v1/users/verify-credentials", strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	require.Equal(t, 200, w.Code)

	var resp struct {
		Data struct {
			Session struct {
				Token string `json:"token"`
			} `json:"session"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.Session.Token)

	session, err := cs.GetSessionForRemoteProxy(context.Background(), resp.Data.Session.Token)
	require.NoError(t, err)

	assert.NotContains(t, session.UserAgent, "\x00", "a NUL byte must never reach the persisted session record")
	assert.NotContains(t, session.UserAgent, "\x07")
	assert.LessOrEqual(t, len(session.UserAgent), maxProxiedUserAgentLen,
		"an oversized User-Agent must be capped before being persisted")
	assert.NotEqual(t, maliciousUA, session.UserAgent)
}

// TestSanitizeProxiedIP and TestSanitizeProxiedUserAgent unit-test the two
// helpers directly.
func TestSanitizeProxiedIP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"valid ipv4", "203.0.113.9", "203.0.113.9"},
		{"valid ipv6", "2001:db8::1", "2001:db8::1"},
		{"embedded newline", "203.0.113.9\r\nfake line", ""},
		{"not an ip at all", "definitely not an ip", ""},
		{"empty", "", ""},
		{"trims surrounding whitespace on a valid ip", "  203.0.113.9  ", "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeProxiedIP(tc.in))
		})
	}
}

func TestSanitizeProxiedUserAgent(t *testing.T) {
	t.Run("strips control characters", func(t *testing.T) {
		got := sanitizeProxiedUserAgent("Mozilla\x00/5.0\r\n(evil)")
		assert.NotContains(t, got, "\x00")
		assert.NotContains(t, got, "\r")
		assert.NotContains(t, got, "\n")
	})
	t.Run("caps length", func(t *testing.T) {
		got := sanitizeProxiedUserAgent(strings.Repeat("A", 10000))
		assert.LessOrEqual(t, len(got), maxProxiedUserAgentLen)
	})
	t.Run("passes through a normal UA unchanged", func(t *testing.T) {
		ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
		assert.Equal(t, ua, sanitizeProxiedUserAgent(ua))
	})
}
