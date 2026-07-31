package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newHygieneTrendsTestHandler(t *testing.T) *HygieneTrendsHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.PersonalAccessToken{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.HygieneTrendSnapshot{},
	))
	return NewHygieneTrendsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func TestGetCredentialTrends_Unauthorized(t *testing.T) {
	h := newHygieneTrendsTestHandler(t)
	w := httptest.NewRecorder()
	h.GetCredentialTrends(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetCredentialTrends_EmptyDB(t *testing.T) {
	h := newHygieneTrendsTestHandler(t)
	w := httptest.NewRecorder()
	h.GetCredentialTrends(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=30", nil)))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestGetCredentialTrends_InvalidDaysDefaultsTo30(t *testing.T) {
	h := newHygieneTrendsTestHandler(t)
	w := httptest.NewRecorder()
	h.GetCredentialTrends(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=banana", nil)))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRecordHygieneSnapshot_Unauthorized(t *testing.T) {
	h := newHygieneTrendsTestHandler(t)
	w := httptest.NewRecorder()
	h.RecordHygieneSnapshot(w, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRecordHygieneSnapshot_EmptyDB(t *testing.T) {
	h := newHygieneTrendsTestHandler(t)
	w := httptest.NewRecorder()
	h.RecordHygieneSnapshot(w, withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
}
