package handlers

// login_storage_error_audit_test.go — the handler-level half of #2745.
//
// The core change gives VerifyPasswordCredentials a distinguishable error class;
// this asserts what the HANDLER then does with it, which is where the defect was
// actually observable: an auth.login_failed audit row for a credential that was
// never checked, and a consumed per-IP login-attempt slot.
//
// Both halves are asserted as EFFECTS — the audit rows actually written and the
// login_attempts rows actually left behind — not as a status code. The status
// deliberately does NOT change (still 401, identical body): a storage error is
// independent of the username supplied, so there is nothing to leak either way,
// and matching FinishWebAuthnLogin's handling (#2565) keeps one shape for the
// whole family.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// usernameLookupDownStore wraps real storage and fails exactly
// GetUserByUsername, with a NON-not-found error — a storage fault, which is the
// case #2745 is about.
type usernameLookupDownStore struct {
	corestorage.Storage
}

func (s *usernameLookupDownStore) GetUserByUsername(context.Context, string) (*models.User, error) {
	return nil, errors.New("pq: connection reset by peer")
}

func TestLogin_UsernameLookupStorageError_AuditsLoginErrorAndReleasesTheSlot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	// A PLAIN :memory: DSN with the pool capped at one connection, not a NAMED
	// shared-cache one. The async audit write below needs every connection to
	// see the same database (a bare :memory: DSN gives each physical connection
	// its own private one, so the goSafe goroutine's row can land somewhere the
	// test's own query never looks) — capping the pool achieves that, same as
	// setupMFAVerifyStorageErrorTest does for the same reason. A named
	// shared-cache DB achieves it too, and was the first thing tried, but it
	// SURVIVES the test: the cache lives as long as the process holds any
	// connection to that name, so under `-count=N` iteration 2 starts with
	// iteration 1's audit row still in place and the exact-count assertion
	// below can never be satisfied (observed: 3 of 5 iterations failing, each
	// burning the full 5s Eventually budget). The exact count is the right
	// assertion — ONE login_error per request, and never a login_failed — so
	// the fixture has to be the thing that is fresh.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.AuditEvent{}, &models.LoginAttempt{}, &models.Session{}))

	h := NewAuthHandler(core.NewKeyorixCore(&usernameLookupDownStore{Storage: store.NewLocalStorage(db)}), false)

	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"ada","password":"hunter2hunter2"}`))
	req.RemoteAddr = "198.51.100.21:5555"
	w := httptest.NewRecorder()
	h.Login(w, req)

	// Unchanged client-facing outcome.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid credentials")

	// The audit write is goSafe'd (asynchronous), exactly as LogAuthFailure
	// always was, so wait for it rather than racing it.
	countEvents := func(eventType string) int64 {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
		return n
	}
	require.Eventually(t, func() bool { return countEvents("auth.login_error") == 1 }, 5*time.Second, 10*time.Millisecond,
		"a username lookup that hit a storage error must be audited as auth.login_error")
	assert.Zero(t, countEvents("auth.login_failed"),
		"and never as auth.login_failed — an incident reviewer counting failed logins against an "+
			"account must not be shown an outage as a bad-credential guess (#2745)")

	// The reserved attempt slot must be given back: the password was never
	// checked against anything, so this is not an attempt in the sense the
	// per-IP budget counts.
	var liveAttempts int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&liveAttempts).Error)
	assert.Zero(t, liveAttempts,
		"the reserved login-attempt slot must be released — a request that was never evaluated must not "+
			"consume the budget a genuine failed attempt does")
}
