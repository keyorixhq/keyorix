package handlers

// machine_token_classify_route_test.go — #2696's happy path, driven through the
// real HTTP handler against real storage.
//
// Everything else that touches this route is coverage-shaped (bad ids, bad
// JSON, missing user context, "not 401"): before this file nothing asserted
// that PATCH .../tokens/{tokenId}/classification actually returns 200 and that
// the label is persisted. #2696 replaces the storage primitive this route
// writes through (the full-row UpdateMachineIdentityCredential becomes the
// column-scoped, conditional SetMachineIdentityCredentialClassification), so
// the route's own success path needs a test that would catch the swap breaking
// it — a structural guard on the write's shape cannot.
//
// Own schema and own DB, deliberately not the shared sticky newHandlerCoreS4
// fixture: this needs seeded project/machine/credential rows, and the shared
// in-memory DB is a conflict hotspot across suites.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

func TestClassifyMachineToken_Route_PersistsLabel_2696(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.OpenWithConfig(t, "kxclassify2696_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.AuditEvent{},
	))

	ls := store.NewLocalStorage(db)
	h := NewCatalogHandler(core.NewKeyorixCore(ls))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "classify-2696"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 1, ProjectID: 1, Name: "ci-bot", State: core.MachineActive}).Error)
	cred, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: 1, Name: "tok", TokenHash: "hash-2696", TokenPrefix: "kx_machine_aa11bb",
	})
	require.NoError(t, err)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	rctx.URLParams.Add("machineId", "1")
	rctx.URLParams.Add("tokenId", strconv.FormatUint(uint64(cred.ID), 10))
	req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{"classification":"restricted"}`))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(),
		customMiddleware.GetUserContextKey(), &customMiddleware.UserContext{UserID: 1, Username: "admin"}))

	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// The label must be PERSISTED, not merely echoed back from the in-memory
	// struct the handler returns (the whole #2696 change is about what reaches
	// the row).
	persisted, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, "restricted", persisted.Classification)
	assert.False(t, persisted.Revoked, "classifying must not change revoked either way")

	// Clearing the label ("" — a map-based Updates, so a zero value really is
	// written rather than skipped as "unset") round-trips too.
	rctx2 := chi.NewRouteContext()
	rctx2.URLParams.Add("id", "1")
	rctx2.URLParams.Add("machineId", "1")
	rctx2.URLParams.Add("tokenId", strconv.FormatUint(uint64(cred.ID), 10))
	req2 := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{"classification":""}`))
	req2 = req2.WithContext(context.WithValue(req2.Context(), chi.RouteCtxKey, rctx2))
	req2 = req2.WithContext(context.WithValue(req2.Context(),
		customMiddleware.GetUserContextKey(), &customMiddleware.UserContext{UserID: 1, Username: "admin"}))
	w2 := httptest.NewRecorder()
	h.ClassifyMachineToken(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code, "body: %s", w2.Body.String())

	cleared, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Empty(t, cleared.Classification, "clearing the classification must persist the empty value")
}
