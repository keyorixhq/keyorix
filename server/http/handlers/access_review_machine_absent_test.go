package handlers

// access_review_machine_absent_test.go — REVIEW-3903-DEEP-2 finding 1.
//
// The ARC-001 machine lookup on access-review revoke/attest/decide answered an absent
// machine id differently (500) from a machine in another project (404), which made the
// status code an existence oracle for machine ids outside the caller's project. Both
// must get the identical answer; a fault on that lookup is a retry answer (503).

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const absentMachineID uint = 9_999_999

func TestAccessReviewMachinePrincipal_AbsentAnswersLikeCrossProject(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	cat := NewCatalogHandler(fw.cs)
	pA := &models.Project{Name: "armabs-a"}
	require.NoError(t, fw.db.Create(pA).Error)
	pB := &models.Project{Name: "armabs-b"}
	require.NoError(t, fw.db.Create(pB).Error)
	creator, err := fw.local.CreateUser(ctx, &models.User{
		Username: "armabs-creator", UsernameFolded: "armabs-creator", Email: "armabs-creator@example.com", EmailFolded: "armabs-creator@example.com",
		IsActive: true, AccountState: "active",
	})
	require.NoError(t, err)
	machineA := &models.MachineIdentity{ProjectID: pA.ID, Name: "armabs-ma", State: "active", CreatedBy: creator.ID}
	require.NoError(t, fw.db.Create(machineA).Error)
	machineB := &models.MachineIdentity{ProjectID: pB.ID, Name: "armabs-mb", State: "active", CreatedBy: creator.ID}
	require.NoError(t, fw.db.Create(machineB).Error)

	type call func(machineID uint) *httptest.ResponseRecorder
	requireSameNotFound := func(t *testing.T, do call, what string) {
		t.Helper()
		cross := do(machineB.ID)
		absent := do(absentMachineID)
		assert.Equal(t, http.StatusNotFound, cross.Code, "%s cross-project: %s", what, cross.Body.String())
		assert.Equal(t, cross.Code, absent.Code, "%s: absent id %s vs cross-project %s", what, absent.Body.String(), cross.Body.String())
		assert.Equal(t, cross.Body.String(), absent.Body.String(), "%s: an absent machine must answer byte-identically to one in another project", what)
	}
	requireLookupFault503 := func(t *testing.T, do call, what string) {
		t.Helper()
		fw.armFault("GetMachineIdentity", 1, assert.AnError)
		w := do(machineA.ID)
		require.True(t, fw.faulty.Fired(), what)
		fw.faulty.Arm(nil)
		requireFold503(t, w, what)
	}

	decision := func(machineID uint) string {
		return `{"source":"role","principal_type":"machine","principal_id":` + suID(machineID) + `,"role_id":1}`
	}
	revoke := func(machineID uint) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		cat.RevokeProjectAccessReview(w, suReq(http.MethodPost, decision(machineID), map[string]string{"id": suID(pA.ID)}))
		return w
	}
	attest := func(machineID uint) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		cat.AttestProjectAccessReview(w, suReq(http.MethodPost, decision(machineID), map[string]string{"id": suID(pA.ID)}))
		return w
	}
	t.Run("revoke", func(t *testing.T) {
		requireSameNotFound(t, revoke, "revoke")
		requireLookupFault503(t, revoke, "revoke GetMachineIdentity fault")
	})
	t.Run("attest", func(t *testing.T) {
		requireSameNotFound(t, attest, "attest")
		requireLookupFault503(t, attest, "attest GetMachineIdentity fault")
	})

	// newCampaign opens a campaign in project A with one pending role item per machine id.
	newCampaign := func(t *testing.T, machineIDs ...uint) (*models.AccessReviewCampaign, map[uint]uint) {
		t.Helper()
		camp := &models.AccessReviewCampaign{ProjectID: pA.ID, Name: "armabs", State: core.CampaignStateOpen, CreatedBy: fw.admin.ID}
		require.NoError(t, fw.db.Create(camp).Error)
		items := map[uint]uint{}
		for _, id := range machineIDs {
			it := &models.AccessReviewItem{CampaignID: camp.ID, PrincipalType: "machine", PrincipalID: id, Source: "role", RoleID: 1, Decision: core.ReviewItemPending}
			require.NoError(t, fw.db.Create(it).Error)
			items[id] = it.ID
		}
		return camp, items
	}
	for _, action := range []string{"attest", "revoke"} {
		t.Run("decide "+action, func(t *testing.T) {
			camp, items := newCampaign(t, machineA.ID, machineB.ID, absentMachineID)
			decide := func(machineID uint) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				cat.DecideAccessReviewCampaignItem(w, suReq(http.MethodPost, `{"action":"`+action+`"}`, map[string]string{
					"id": suID(pA.ID), "campaignId": suID(camp.ID), "itemId": suID(items[machineID]),
				}))
				return w
			}
			requireSameNotFound(t, decide, "decide "+action)
			requireLookupFault503(t, decide, "decide "+action+" GetMachineIdentity fault")
		})
	}

	t.Run("force close", func(t *testing.T) {
		camp, _ := newCampaign(t, absentMachineID)
		closeCampaign := func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.CloseAccessReviewCampaign(w, suReq(http.MethodPost, `{"force":true}`, map[string]string{"id": suID(pA.ID), "campaignId": suID(camp.ID)}))
			return w
		}
		fw.armFault("GetMachineIdentity", 1, assert.AnError)
		w := closeCampaign()
		require.True(t, fw.faulty.Fired())
		fw.faulty.Arm(nil)
		requireFold503(t, w, "force close GetMachineIdentity fault")

		w = closeCampaign()
		assert.Equal(t, http.StatusNotFound, w.Code, "a pending item for a machine that no longer exists stays 404: %s", w.Body.String())
		assert.NotContains(t, w.Body.String(), "record not found", "the driver text must not reach the client")
	})
}
