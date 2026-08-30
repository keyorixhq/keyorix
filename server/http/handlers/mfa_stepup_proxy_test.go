package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var stepupProxyDBCounter atomic.Int64

// freshCoreWithStepUpGrant builds a core that has the MFAStepUpGrant table and
// seeds one active grant for user 1 at the given expiry.
func freshCoreWithStepUpGrant(t *testing.T, expiry time.Time) (*AuthHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	n := stepupProxyDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxstepupprx_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.MFAStepUpGrant{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID:    1,
		ExpiresAt: expiry,
	}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	return NewAuthHandler(cs, false), db
}

// ── GetActiveMFAStepUpGrantProxy ──────────────────────────────────────────────

func TestGetActiveMFAStepUpGrantProxy_BadJSON(t *testing.T) {
	h := freshClosedCoreS21(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/active",
		bytes.NewReader([]byte("{bad json}")))
	w := httptest.NewRecorder()
	h.GetActiveMFAStepUpGrantProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetActiveMFAStepUpGrantProxy_MissingUserID(t *testing.T) {
	h := freshClosedCoreS21(t)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": 0,
		"now":     time.Now().UTC(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/active",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.GetActiveMFAStepUpGrantProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetActiveMFAStepUpGrantProxy_StorageError(t *testing.T) {
	h := freshClosedCoreS21(t)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": 1,
		"now":     time.Now().UTC(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/active",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.GetActiveMFAStepUpGrantProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetActiveMFAStepUpGrantProxy_NoActiveGrant(t *testing.T) {
	h, _ := freshCoreWithStepUpGrant(t, time.Now().UTC().Add(10*time.Minute))
	// Ask for user 99 — no grant exists.
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": 99,
		"now":     time.Now().UTC(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/active",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.GetActiveMFAStepUpGrantProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	// data is omitted (omitempty on nil) — no grant means no data field.
	assert.NotContains(t, w.Body.String(), `"user_id"`)
}

func TestGetActiveMFAStepUpGrantProxy_ActiveGrant(t *testing.T) {
	future := time.Now().UTC().Add(10 * time.Minute)
	h, _ := freshCoreWithStepUpGrant(t, future)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": 1,
		"now":     time.Now().UTC(),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/active",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.GetActiveMFAStepUpGrantProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			UserID uint `json:"user_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, uint(1), resp.Data.UserID)
}
