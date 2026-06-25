// access_review_campaign.go — periodic access-recertification campaigns (ISO 27001
// A.5.18, "review access rights at planned intervals"). A campaign turns the
// point-in-time access review (access_review.go) into a managed cycle:
//
//   - Open  — snapshot the project's current access-review entries into immutable
//     campaign items (each "pending"). Audited access_review.campaign_opened.
//   - Decide — a reviewer attests (keeps) or revokes each item; revoke removes the
//     underlying grant via RevokeAccessReviewGrant. Each decision is audited.
//   - Close — freeze the campaign as evidence the review was performed; refuses
//     while items are still pending unless forced. Audited access_review.campaign_closed.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Campaign + item states and decision actions.
const (
	CampaignStateOpen   = "open"
	CampaignStateClosed = "closed"

	ReviewItemPending  = "pending"
	ReviewItemAttested = "attested"
	ReviewItemRevoked  = "revoked"

	EventCampaignOpened = "access_review.campaign_opened" // #nosec G101 -- audit event type, not a credential
	EventCampaignClosed = "access_review.campaign_closed" // #nosec G101 -- audit event type, not a credential
)

// CampaignProgress summarises a campaign's recertification state.
type CampaignProgress struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Attested int `json:"attested"`
	Revoked  int `json:"revoked"`
}

// CampaignWithProgress is a campaign plus its decision tally (for list views).
type CampaignWithProgress struct {
	Campaign *models.AccessReviewCampaign `json:"campaign"`
	Progress CampaignProgress             `json:"progress"`
}

// CampaignDetail is a campaign with its items and progress (for the detail view).
type CampaignDetail struct {
	Campaign *models.AccessReviewCampaign `json:"campaign"`
	Items    []*models.AccessReviewItem   `json:"items"`
	Progress CampaignProgress             `json:"progress"`
}

func tallyProgress(items []*models.AccessReviewItem) CampaignProgress {
	p := CampaignProgress{Total: len(items)}
	for _, it := range items {
		switch it.Decision {
		case ReviewItemAttested:
			p.Attested++
		case ReviewItemRevoked:
			p.Revoked++
		default:
			p.Pending++
		}
	}
	return p
}

// OpenAccessReviewCampaign snapshots the project's current access review into a new
// campaign's items (each pending) and returns the campaign with its (all-pending)
// progress. actorID is the opener.
func (c *KeyorixCore) OpenAccessReviewCampaign(ctx context.Context, actorID, projectID uint, name string) (*CampaignWithProgress, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	entries, err := c.GenerateProjectAccessReview(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "Access review"
	}
	campaign, err := c.storage.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID,
		Name:      name,
		State:     CampaignStateOpen,
		CreatedBy: actorID,
		CreatedAt: c.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	items := make([]*models.AccessReviewItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, &models.AccessReviewItem{
			CampaignID:    campaign.ID,
			PrincipalType: e.PrincipalType,
			PrincipalID:   e.PrincipalID,
			PrincipalName: e.PrincipalName,
			Email:         e.Email,
			Source:        e.Source,
			RoleID:        e.RoleID,
			RoleName:      e.RoleName,
			AccessLevel:   e.AccessLevel,
			EnvironmentID: e.EnvironmentID,
			SecretID:      e.SecretID,
			SecretName:    e.SecretName,
			LastUsedAt:    e.LastUsedAt,
			Decision:      ReviewItemPending,
		})
	}
	if err := c.storage.CreateAccessReviewItems(ctx, items); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.auditProjectScoped(ctx, EventCampaignOpened, actorID, projectID,
		fmt.Sprintf("opened access-review campaign %d (%q) with %d item(s)", campaign.ID, name, len(items)))
	return &CampaignWithProgress{Campaign: campaign, Progress: CampaignProgress{Total: len(items), Pending: len(items)}}, nil
}

// ListAccessReviewCampaigns returns the project's campaigns, newest first, each
// with its decision tally.
func (c *KeyorixCore) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*CampaignWithProgress, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	campaigns, err := c.storage.ListAccessReviewCampaigns(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make([]*CampaignWithProgress, 0, len(campaigns))
	for _, camp := range campaigns {
		items, err := c.storage.ListAccessReviewItems(ctx, camp.ID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		out = append(out, &CampaignWithProgress{Campaign: camp, Progress: tallyProgress(items)})
	}
	return out, nil
}

// loadScopedCampaign fetches a campaign and enforces that it belongs to projectID
// (so a campaign id from another project cannot be reached through this project's
// scope — the same cross-project guard as the access-request flow).
func (c *KeyorixCore) loadScopedCampaign(ctx context.Context, projectID, campaignID uint) (*models.AccessReviewCampaign, error) {
	campaign, err := c.storage.GetAccessReviewCampaign(ctx, campaignID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if campaign.ProjectID != projectID {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return campaign, nil
}

// GetAccessReviewCampaign returns a campaign (scoped to projectID), its items, and
// its progress.
func (c *KeyorixCore) GetAccessReviewCampaign(ctx context.Context, projectID, campaignID uint) (*CampaignDetail, error) {
	campaign, err := c.loadScopedCampaign(ctx, projectID, campaignID)
	if err != nil {
		return nil, err
	}
	items, err := c.storage.ListAccessReviewItems(ctx, campaignID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &CampaignDetail{Campaign: campaign, Items: items, Progress: tallyProgress(items)}, nil
}

// DecideAccessReviewItem records a reviewer's decision on one item of an open
// campaign: "attest" keeps the grant (evidence only), "revoke" removes the
// underlying grant via RevokeAccessReviewGrant. actorID is the reviewer.
func (c *KeyorixCore) DecideAccessReviewItem(ctx context.Context, actorID, projectID, campaignID, itemID uint, action, reason string) error {
	campaign, err := c.loadScopedCampaign(ctx, projectID, campaignID)
	if err != nil {
		return err
	}
	if campaign.State != CampaignStateOpen {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "campaign is closed; decisions can only be made on an open campaign")
	}
	item, err := c.storage.GetAccessReviewItem(ctx, itemID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if item.CampaignID != campaignID {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	// Decide once: an already-attested/revoked item must not be flipped. A revoke
	// removes the real grant, so re-deciding it (revoke→attest) would record
	// "attested" for access that no longer exists — false certification evidence.
	if item.Decision != ReviewItemPending {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this item has already been decided")
	}
	// Independence (ISO 27001 A.5.18): a reviewer must not certify their OWN access —
	// directly (a user-scoped item that is themselves) OR indirectly (a group-scoped item
	// for a group they belong to). Self-certification, including via a group grant,
	// defeats the control; an independent reviewer is required.
	if item.PrincipalType == "user" && item.PrincipalID == actorID {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot review your own access; an independent reviewer is required")
	}
	if item.PrincipalType == "group" && c.userInGroup(ctx, actorID, item.PrincipalID) {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot review access for a group you belong to; an independent reviewer is required")
	}

	decision := AccessReviewDecision{
		Source:        item.Source,
		PrincipalType: item.PrincipalType,
		PrincipalID:   item.PrincipalID,
		RoleID:        item.RoleID,
		EnvironmentID: item.EnvironmentID,
		SecretID:      item.SecretID,
	}
	switch action {
	case "attest":
		if err := c.AttestAccessReviewGrant(ctx, actorID, projectID, decision); err != nil {
			return err
		}
		item.Decision = ReviewItemAttested
	case "revoke":
		if err := c.RevokeAccessReviewGrant(ctx, actorID, projectID, decision); err != nil {
			return err
		}
		item.Decision = ReviewItemRevoked
	default:
		return fmt.Errorf("%s: action must be attest or revoke", i18n.T("ErrorValidation", nil))
	}
	now := c.now()
	item.Reason = reason
	item.DecidedBy = actorID
	item.DecidedAt = &now
	if err := c.storage.UpdateAccessReviewItem(ctx, item); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// userInGroup reports whether userID is a member of groupID. It fails CLOSED — a
// lookup error returns true — because it backs the recertification independence check:
// if we can't prove the reviewer is NOT in the group, we must not let them certify it.
func (c *KeyorixCore) userInGroup(ctx context.Context, userID, groupID uint) bool {
	groups, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		return true
	}
	for _, g := range groups {
		if g.ID == groupID {
			return true
		}
	}
	return false
}

// CloseAccessReviewCampaign freezes a campaign as the evidence record. It refuses
// while items remain pending unless force is set (so an auditor sees either a fully
// decided cycle or an explicit early close). actorID is the closer.
func (c *KeyorixCore) CloseAccessReviewCampaign(ctx context.Context, actorID, projectID, campaignID uint, force bool) (*CampaignWithProgress, error) {
	campaign, err := c.loadScopedCampaign(ctx, projectID, campaignID)
	if err != nil {
		return nil, err
	}
	if campaign.State == CampaignStateClosed {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "campaign is already closed")
	}
	items, err := c.storage.ListAccessReviewItems(ctx, campaignID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	progress := tallyProgress(items)
	if progress.Pending > 0 && !force {
		return nil, fmt.Errorf("%s: %d item(s) still pending — decide them or close with force", i18n.T("ErrorValidation", nil), progress.Pending)
	}
	now := c.now()
	campaign.State = CampaignStateClosed
	campaign.ClosedBy = actorID
	campaign.ClosedAt = &now
	if err := c.storage.UpdateAccessReviewCampaign(ctx, campaign); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.auditProjectScoped(ctx, EventCampaignClosed, actorID, projectID,
		fmt.Sprintf("closed access-review campaign %d: %d attested, %d revoked, %d pending of %d",
			campaign.ID, progress.Attested, progress.Revoked, progress.Pending, progress.Total))
	return &CampaignWithProgress{Campaign: campaign, Progress: progress}, nil
}
