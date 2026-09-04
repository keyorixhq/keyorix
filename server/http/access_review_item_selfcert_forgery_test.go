// access_review_item_selfcert_forgery_test.go — documented-exception
// re-verification finding (2026-09-04): UpdateAccessReviewItemProxy's
// self-certification check (ARC-005) compared the authenticated caller
// against CLIENT-SUPPLIED body.PrincipalType/body.PrincipalID instead of the
// item's real, server-side principal. A caller could lie about
// PrincipalType (e.g. claim "role" for a row the DB actually records as
// "user") to skip the check entirely, then self-certify their own
// access-review item -- the exact adversary class the check's own doc
// comment claims to defend against. Compounding this, the wire body's
// PrincipalType/PrincipalID were persisted verbatim, corrupting the
// frozen-at-campaign-open evidence snapshot the endpoint exists to preserve.
// See TestWireActorForgery_UpdateAccessReviewItemProxy_CannotSelfCertify in
// wire_actor_identity_forgery_test.go for the sibling "name someone else in
// decided_by" variant this same ARC-005 comment already closed.
package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestUpdateAccessReviewItemProxy_CannotSelfCertifyByLyingAboutPrincipalType(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	campaign, err := f.core.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: f.projectID, Name: "selfcert-forge-campaign", State: "open", CreatedBy: f.adminID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, f.core.Storage().CreateAccessReviewItems(ctx, []*models.AccessReviewItem{{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: f.adminID, PrincipalName: "admin",
		Source: "role", AccessLevel: "read", Decision: "pending",
	}}))
	items, err := f.core.Storage().ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, err)
	require.Len(t, items, 1)
	itemID := items[0].ID

	// The item's own subject (admin) tries to certify it, this time lying
	// about principal_type ("role" instead of the DB row's real "user") to
	// slip past the naive `body.PrincipalType == "user"` check -- must still
	// be refused, because the check now anchors to the SERVER-FETCHED item,
	// not the wire body.
	adminToken := createTestToken(t, f.core)
	status, body := f.do(t, adminToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", itemID), map[string]any{
		"campaign_id": campaign.ID, "principal_type": "role", "principal_id": f.adminID, "decision": "attested",
	})
	t.Logf("PUT .../items/%d (subject self-certifying, principal_type lied to \"role\"): status=%d body=%s", itemID, status, body)
	require.Equal(t, http.StatusForbidden, status, "the item's own subject must not be able to self-certify by lying about principal_type on the wire")

	fetched, err := f.core.Storage().GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)
	require.Equal(t, "pending", fetched.Decision, "the item must remain pending after a refused self-certification attempt")
	require.Equal(t, "user", fetched.PrincipalType, "the item's real principal_type must not be overwritten by the attacker's fabricated wire value")
}

// TestUpdateAccessReviewItemProxy_WireFieldsCannotOverwritePrincipal proves
// the second half of the fix: even a LEGITIMATE, non-self-certifying
// reviewer cannot use this endpoint to rewrite the item's identity fields
// (principal_type/principal_id/campaign_id/etc) -- only the decision fields
// (decision/reason/decided_by/decided_at) are ever caller-writable.
func TestUpdateAccessReviewItemProxy_WireFieldsCannotOverwritePrincipal(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	campaign, err := f.core.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: f.projectID, Name: "wire-overwrite-campaign", State: "open", CreatedBy: f.adminID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, f.core.Storage().CreateAccessReviewItems(ctx, []*models.AccessReviewItem{{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: f.adminID, PrincipalName: "real-name",
		Source: "role", AccessLevel: "read", Decision: "pending",
	}}))
	items, err := f.core.Storage().ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, err)
	require.Len(t, items, 1)
	itemID := items[0].ID

	// A genuine, independent reviewer certifies the item, but ALSO tries to
	// smuggle a rewritten principal_id/principal_name/campaign_id on the
	// wire -- none of it must persist; only decision/reason/decided_by/
	// decided_at are caller-writable.
	status, body := f.do(t, f.assignToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", itemID), map[string]any{
		"campaign_id": campaign.ID + 999, "principal_type": "user", "principal_id": f.adminID + 1, "principal_name": "forged-name",
		"decision": "attested", "reason": "looks fine",
	})
	t.Logf("PUT .../items/%d (real reviewer, wire tries to rewrite principal fields): status=%d body=%s", itemID, status, body)
	require.Equal(t, http.StatusOK, status, "a genuine, non-self-certifying reviewer must still be able to certify")

	fetched, err := f.core.Storage().GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)
	require.Equal(t, "attested", fetched.Decision)
	require.Equal(t, campaign.ID, fetched.CampaignID, "campaign_id must not be rewritable via this endpoint")
	require.Equal(t, f.adminID, fetched.PrincipalID, "principal_id must not be rewritable via this endpoint")
	require.Equal(t, "real-name", fetched.PrincipalName, "principal_name must not be rewritable via this endpoint")
}
