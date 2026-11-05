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

// STORAGE-ERR-CLASS-5 item 2: the access-review reads that are not a verdict on a named
// target (the campaign and item listings, a force-close's group-membership lookup, the
// project access report's grant and secret listings) answer
// 503 storage_unavailable on a storage fault; a campaign that does not exist stays 404.
func TestAccessReviewReads_FaultIs503(t *testing.T) {
	fw := newFoldWorld(t)
	cat := NewCatalogHandler(fw.cs)
	p := &models.Project{Name: "ar-reads-proj"}
	require.NoError(t, fw.db.Create(p).Error)
	grp := &models.Group{Name: "ar-reads-group"}
	require.NoError(t, fw.db.Create(grp).Error)
	camp := &models.AccessReviewCampaign{ProjectID: p.ID, Name: "q", State: core.CampaignStateOpen, CreatedBy: fw.admin.ID}
	require.NoError(t, fw.db.Create(camp).Error)
	require.NoError(t, fw.db.Create(&models.AccessReviewItem{
		CampaignID: camp.ID, PrincipalType: "group", PrincipalID: grp.ID, Source: "role", Decision: core.ReviewItemPending,
	}).Error)
	params := func(campaignID uint) map[string]string {
		return map[string]string{"id": suID(p.ID), "campaignId": suID(campaignID)}
	}

	for _, tc := range []struct {
		name, method string
		call         func(w http.ResponseWriter, r *http.Request)
		body         string
	}{
		{"ListAccessReviewCampaigns items", "ListAccessReviewItems", cat.ListAccessReviewCampaigns, ""},
		{"GetAccessReviewCampaign items", "ListAccessReviewItems", cat.GetAccessReviewCampaign, ""},
		{"CloseAccessReviewCampaign items", "ListAccessReviewItems", cat.CloseAccessReviewCampaign, `{"force":true}`},
		{"CloseAccessReviewCampaign group membership", "GetUserGroups", cat.CloseAccessReviewCampaign, `{"force":true}`},
		{"GetProjectAccessReview role grants", "ListProjectRoleAssignments", cat.GetProjectAccessReview, ""},
		{"GetProjectAccessReview machine grants", "ListProjectMachineRoleAssignments", cat.GetProjectAccessReview, ""},
		{"GetProjectAccessReview secrets", "ListSecrets", cat.GetProjectAccessReview, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw.faulty.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			defer fw.faulty.Arm(nil)
			w := httptest.NewRecorder()
			tc.call(w, suReq(http.MethodPost, tc.body, params(camp.ID)))
			require.True(t, fw.faulty.Fired())
			requireFold503(t, w, tc.name)
		})
	}

	w := httptest.NewRecorder()
	cat.GetAccessReviewCampaign(w, suReq(http.MethodGet, "", params(9_999_999)))
	assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404: %s", w.Body.String())
	assert.Empty(t, w.Header().Get("Retry-After"))
}
