package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// fakeInviteDeliverer is an always-succeeding credential delivery stub so a
// test can get past provisionSetupLink's base_url check and reach
// IssueSetupToken's own storage transaction.
type fakeInviteDeliverer struct{}

func (f *fakeInviteDeliverer) DeliverSetupLink(_ context.Context, _ delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	return delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}, nil
}

func (f *fakeInviteDeliverer) Name() string { return "fake" }

var errInjectedInviteFault = errors.New("injected storage fault")

// setupInvitationFaultTest builds a CatalogHandler over a real SQLite-backed
// KeyorixCore wrapped in a FaultyStorage, with credential delivery configured
// so an invitation create reaches setup-token issuance instead of stopping at
// the base_url check.
func setupInvitationFaultTest(t *testing.T) (*CatalogHandler, *gorm.DB, *faultstorage.FaultyStorage) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.UserRole{}, &models.Role{}, &models.Project{},
		&models.ProjectInvitation{}, &models.SetupToken{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Environment{},
		&models.Permission{}, &models.RolePermission{},
	))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "system_auditor"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.Project{Name: "default"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "testuser", Email: "testuser@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 100, Name: "super_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 100, ProjectID: 0}).Error)

	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := core.NewKeyorixCore(faulty)
	c.SetCredentialDelivery(&fakeInviteDeliverer{}, "https://keyorix.test")
	return NewCatalogHandler(c), db, faulty
}

// TestCreateGlobalInvitation_SupersedeActiveSetupTokensErrorFailsClosed and its
// project-scoped sibling below are the HTTP-layer regression tests for #2419:
// a failed supersede+create of the setup token must return an error status,
// not the 201 "created" response CreateGlobalInvitation/CreateInvitation send
// for a benign config/throttle/delivery failure.
func TestCreateGlobalInvitation_SupersedeActiveSetupTokensErrorFailsClosed(t *testing.T) {
	h, db, faulty := setupInvitationFaultTest(t)
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errInjectedInviteFault,
	})

	w := postGlobalInvite(t, h, `{"email":"carol@acme.io","role":"system_auditor"}`)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"a failed supersede+create must not be reported as 201 success")
	assert.NotContains(t, w.Body.String(), "delivery_error",
		"this is not the benign delivery-failure partial-success shape")

	// #2444 coordinator follow-up: neither the invitation nor a setup token
	// may exist after the fault -- the insert and the mint now commit or
	// fail together.
	var n int64
	require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "carol@acme.io").Count(&n).Error)
	assert.Zero(t, n, "no invitation row should exist after a rolled-back issuance")
	require.NoError(t, db.Model(&models.SetupToken{}).Where("subject_email = ?", "carol@acme.io").Count(&n).Error)
	assert.Zero(t, n, "no setup token should exist after a rolled-back issuance")
}

// TestCreateGlobalInvitation_SupersedeActiveSetupTokensError_RetrySucceeds
// proves the fail-closed fix actually unblocks recovery: an immediate retry
// of the exact same invite, once the fault clears, must succeed with no
// leftover state from the failed attempt in the way.
func TestCreateGlobalInvitation_SupersedeActiveSetupTokensError_RetrySucceeds(t *testing.T) {
	h, db, faulty := setupInvitationFaultTest(t)
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errInjectedInviteFault,
	})
	w := postGlobalInvite(t, h, `{"email":"carol@acme.io","role":"system_auditor"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)

	w2 := postGlobalInvite(t, h, `{"email":"carol@acme.io","role":"system_auditor"}`)
	assert.Equal(t, http.StatusCreated, w2.Code, "an immediate retry after a rolled-back attempt must succeed")

	var n int64
	require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "carol@acme.io").Count(&n).Error)
	assert.Equal(t, int64(1), n, "exactly one invitation should exist after the failed attempt rolled back and the retry succeeded")
}

func TestCreateInvitation_SupersedeActiveSetupTokensErrorFailsClosed(t *testing.T) {
	h, db, faulty := setupInvitationFaultTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errInjectedInviteFault,
	})

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewReader([]byte(`{"email":"dave@acme.io","role":"project_developer"}`))), "id", strconv.Itoa(int(proj.ID))))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"a failed supersede+create must not be reported as 201 success")

	var n int64
	require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "dave@acme.io").Count(&n).Error)
	assert.Zero(t, n, "no invitation row should exist after a rolled-back issuance")
	require.NoError(t, db.Model(&models.SetupToken{}).Where("subject_email = ?", "dave@acme.io").Count(&n).Error)
	assert.Zero(t, n, "no setup token should exist after a rolled-back issuance")
}

// TestCreateInvitation_SupersedeActiveSetupTokensError_RetrySucceeds is the
// project-scoped sibling of the global-invite retry test above.
func TestCreateInvitation_SupersedeActiveSetupTokensError_RetrySucceeds(t *testing.T) {
	h, db, faulty := setupInvitationFaultTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errInjectedInviteFault,
	})

	body := `{"email":"dave@acme.io","role":"project_developer"}`
	req1 := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body))), "id", strconv.Itoa(int(proj.ID))))
	w1 := httptest.NewRecorder()
	h.CreateInvitation(w1, req1)
	require.Equal(t, http.StatusInternalServerError, w1.Code)

	req2 := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body))), "id", strconv.Itoa(int(proj.ID))))
	w2 := httptest.NewRecorder()
	h.CreateInvitation(w2, req2)
	assert.Equal(t, http.StatusCreated, w2.Code, "an immediate retry after a rolled-back attempt must succeed")

	var n int64
	require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "dave@acme.io").Count(&n).Error)
	assert.Equal(t, int64(1), n, "exactly one invitation should exist after the failed attempt rolled back and the retry succeeded")
}
