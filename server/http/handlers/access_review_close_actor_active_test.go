package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCloseAccessReviewCampaign_ActorActiveAtTransport (#4546, L-3 of
// REVIEW-4613-DEEP-1): CloseAccessReviewCampaign reads the acting account first
// (requireActorActive). Over REST an inactive actor answers 400 (this route's status
// for a typed permission refusal, campaignStatusForError) and a failed read of the
// account answers 503 storage_unavailable with Retry-After. Either way the campaign
// stays open.
func TestCloseAccessReviewCampaign_ActorActiveAtTransport(t *testing.T) {
	fw := newFoldWorld(t)
	cat := NewCatalogHandler(fw.cs)
	p := &models.Project{Name: "ar-close-actor-proj"}
	require.NoError(t, fw.db.Create(p).Error)
	camp := &models.AccessReviewCampaign{ProjectID: p.ID, Name: "q", State: core.CampaignStateOpen, CreatedBy: fw.admin.ID}
	require.NoError(t, fw.db.Create(camp).Error)
	params := map[string]string{"id": suID(p.ID), "campaignId": suID(camp.ID)}
	requireStillOpen := func(t *testing.T) {
		t.Helper()
		var got models.AccessReviewCampaign
		require.NoError(t, fw.db.First(&got, camp.ID).Error)
		assert.Equal(t, core.CampaignStateOpen, got.State, "a refused close must leave the campaign open")
	}

	t.Run("actor read fault is 503", func(t *testing.T) {
		fw.faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
		defer fw.faulty.Arm(nil)
		w := httptest.NewRecorder()
		cat.CloseAccessReviewCampaign(w, suReq(http.MethodPost, `{"force":true}`, params))
		require.True(t, fw.faulty.Fired())
		requireFold503(t, w, "close with actor read fault")
		requireStillOpen(t)
	})

	t.Run("inactive actor is 400", func(t *testing.T) {
		require.NoError(t, fw.db.Model(&models.User{}).Where("id = ?", fw.admin.ID).Update("is_active", false).Error)
		w := httptest.NewRecorder()
		cat.CloseAccessReviewCampaign(w, suReq(http.MethodPost, `{"force":true}`, params))
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Empty(t, w.Header().Get("Retry-After"), "a refusal is not a retryable outage")
		requireStillOpen(t)
	})
}
