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
	// Note: opening is NOT gated on a human actor — the scheduler legitimately auto-opens
	// overdue campaigns as a system action (actorID==0). Opening only generates review
	// items; the attributable-human requirement is enforced on the DECISION (attest/
	// revoke) in DecideAccessReviewItem, which is the actual recertification control.
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	report, err := c.GenerateProjectAccessReview(ctx, projectID)
	if err != nil {
		return nil, err
	}
	entries := report.Entries
	if name == "" {
		name = "Access review"
	}
	// #483: report.Degraded/DegradedReasons signal a transient storage error mid-
	// snapshot (e.g. one secret's shares couldn't be read); persist them onto the
	// campaign row itself instead of discarding them the instant the report is
	// consumed — an ephemeral return value is not a durable record that this
	// recertification cycle's evidence snapshot was incomplete.
	campaign, err := c.storage.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID:       projectID,
		Name:            name,
		State:           CampaignStateOpen,
		CreatedBy:       actorID,
		CreatedAt:       c.now(),
		Degraded:        report.Degraded,
		DegradedReasons: report.DegradedReasons,
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

// AuditCampaignCreated emits the campaign_opened audit event on behalf of a
// proxy caller (e.g. CreateAccessReviewCampaignProxy) that already ran the
// OpenAccessReviewCampaign business logic on the downstream server and only
// persisted the raw campaign row here. The proxy calls this after a successful
// CreateAccessReviewCampaign storage write to keep the upstream audit trail
// consistent with the human-facing OpenAccessReviewCampaign path.
func (c *KeyorixCore) AuditCampaignCreated(ctx context.Context, actorID, projectID, campaignID uint, name string, itemCount int) {
	c.auditProjectScoped(ctx, EventCampaignOpened, actorID, projectID,
		fmt.Sprintf("opened access-review campaign %d (%q) with %d item(s) [via proxy]", campaignID, name, itemCount))
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
// checkReviewerIndependence enforces ISO 27001 A.5.18: a reviewer must not certify
// their own access, directly (user-scoped item) or via group membership. Fails closed:
// a group-lookup error is treated as membership to block self-certification by error.
// checkReviewerIndependence takes the normalized principal type/ID directly
// (not an *models.AccessReviewItem) so the SAME check can gate both the
// campaign flow (DecideAccessReviewItem, via item.PrincipalType/PrincipalID)
// and the standalone attest/revoke endpoints (#G52, via
// principalTypeForDecision's inference — AccessReviewDecision.PrincipalType
// is only ever populated by the caller for "role" sources).
func (c *KeyorixCore) checkReviewerIndependence(ctx context.Context, actorID uint, principalType string, principalID uint) error {
	if principalType == "user" && principalID == actorID {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot review your own access; an independent reviewer is required")
	}
	if principalType == "group" && c.userInGroup(ctx, actorID, principalID) {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot review access for a group you belong to; an independent reviewer is required")
	}
	return nil
}

// applyAccessDecision executes the grant action (attest or revoke) and stamps the
// item's Decision field. Extracted from DecideAccessReviewItem to reduce its complexity.
func (c *KeyorixCore) applyAccessDecision(ctx context.Context, actorID, projectID uint, item *models.AccessReviewItem, action string, decision AccessReviewDecision) error {
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
	return nil
}

// persistItemDecision persists the decided item via a conditional UPDATE that also
// guards the race between concurrent decisions and concurrent force-closes (#319, #343).
// ok==false means this call lost the race; the re-read is cosmetic only — the security
// decision was already made atomically by the UPDATE, win or lose.
func (c *KeyorixCore) persistItemDecision(ctx context.Context, item *models.AccessReviewItem, itemID uint) error {
	ok, err := c.storage.UpdateAccessReviewItem(ctx, item)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !ok {
		if reloaded, rerr := c.storage.GetAccessReviewItem(ctx, itemID); rerr == nil && reloaded.Decision != ReviewItemPending {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this item has already been decided")
		}
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "campaign is closed; decisions can only be made on an open campaign")
	}
	return nil
}

func (c *KeyorixCore) DecideAccessReviewItem(ctx context.Context, actorID, projectID, campaignID, itemID uint, action, reason string) error {
	// A recertification decision must come from an attributable HUMAN reviewer. A
	// machine identity authenticates with UserID==0 (authz uses its PrincipalID), so a
	// non-zero actorID is required — otherwise an automation token holding roles.assign
	// could rubber-stamp a campaign with the evidence recording reviewer "0"/nil, and the
	// self-review independence check below (keyed on actorID) would be a no-op for it.
	if err := requireHumanReviewer(actorID); err != nil {
		return err
	}
	campaign, err := c.loadScopedCampaign(ctx, projectID, campaignID)
	if err != nil {
		return err
	}
	if campaign.State != CampaignStateOpen {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "campaign is closed; decisions can only be made on an open campaign")
	}
	// #G04/HA: WithAccessReviewDecisionLock holds from the pending-decision read
	// through the actual attest/revoke side effect and its persisted stamp —
	// see its doc comment in internal/core/storage/interface.go for why
	// persistItemDecision's conditional UPDATE alone isn't enough (it stops a
	// second STAMP from persisting, not a second ACTION from executing), and
	// why the former in-process-only accessReviewDecisionMu provided no
	// serialization at all between two HA replicas sharing the same Postgres
	// database (#G04-HA).
	return c.storage.WithAccessReviewDecisionLock(ctx, func() error {
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
		if err := c.checkReviewerIndependence(ctx, actorID, item.PrincipalType, item.PrincipalID); err != nil {
			return err
		}
		// ARC-001: a machine identity provisioned by the actor must not be self-certified
		// by its creator. Fail closed on lookup error (can't prove independence → deny).
		if item.PrincipalType == "machine" {
			machine, err := c.storage.GetMachineIdentity(ctx, item.PrincipalID)
			if err != nil {
				return fmt.Errorf("loading machine identity: %w", err)
			}
			if machine.CreatedBy == actorID {
				return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "independent reviewer required for machine identities you provisioned")
			}
		}
		decision := AccessReviewDecision{
			Source:        item.Source,
			PrincipalType: item.PrincipalType,
			PrincipalID:   item.PrincipalID,
			RoleID:        item.RoleID,
			EnvironmentID: item.EnvironmentID,
			SecretID:      item.SecretID,
		}
		if err := c.applyAccessDecision(ctx, actorID, projectID, item, action, decision); err != nil {
			return err
		}
		now := c.now()
		item.Reason = reason
		item.DecidedBy = actorID
		item.DecidedAt = &now
		return c.persistItemDecision(ctx, item, itemID)
	})
}

// requireHumanReviewer rejects a recertification action by a non-human / unattributable
// actor. A machine identity authenticates with UserID==0 (it authorizes via PrincipalID),
// and actorID==0 also denotes an unauthenticated local invocation — neither is an
// attributable, independent human reviewer, which the SOC2/ISO/NIS2 control requires.
func requireHumanReviewer(actorID uint) error {
	if actorID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "access reviews require an attributable human reviewer (a machine identity cannot act as a reviewer)")
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

// checkMachineIndependence verifies the actor did not provision the machine identity
// behind a pending review item. Fails closed on lookup error (AUD-010).
func (c *KeyorixCore) checkMachineIndependence(ctx context.Context, actorID uint, principalID uint) error {
	machine, err := c.storage.GetMachineIdentity(ctx, principalID)
	if err != nil {
		return fmt.Errorf("loading machine identity for independence check: %w", err)
	}
	if machine.CreatedBy == actorID {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot force-close a campaign while an access item for a machine identity you provisioned is still pending; an independent reviewer must decide it first")
	}
	return nil
}

// checkForceCloseIndependence ensures the actor does not have a conflict of interest
// in any pending review item before a force-close is allowed (ARC-002).
func (c *KeyorixCore) checkForceCloseIndependence(ctx context.Context, actorID uint, items []*models.AccessReviewItem) error {
	for _, it := range items {
		if it.Decision != ReviewItemPending {
			continue
		}
		if it.PrincipalType == "user" && it.PrincipalID == actorID {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot force-close a campaign while your own access item is still pending; an independent reviewer must decide it first")
		}
		if it.PrincipalType == "group" && c.userInGroup(ctx, actorID, it.PrincipalID) {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you cannot force-close a campaign while an access item for a group you belong to is still pending; an independent reviewer must decide it first")
		}
		if it.PrincipalType == "machine" {
			if err := c.checkMachineIndependence(ctx, actorID, it.PrincipalID); err != nil {
				return err
			}
		}
	}
	return nil
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
	// ARC-002: even a forced close must not let the actor suppress their own
	// undecided access item — that would allow the closer to silently freeze a
	// campaign before an independent reviewer could decide on their grant.
	// Mirror the DecideAccessReviewItem independence check: fail closed on lookup.
	if force && progress.Pending > 0 {
		if err := c.checkForceCloseIndependence(ctx, actorID, items); err != nil {
			return nil, err
		}
	}
	now := c.now()
	campaign.State = CampaignStateClosed
	campaign.ClosedBy = actorID
	campaign.ClosedAt = &now
	// #237: a forced close with items still pending freezes the campaign as
	// evidence, but it is NOT a genuine, fully-decided recertification cycle —
	// some access was never reviewed. Without this signal, ClosedAt alone makes
	// this close indistinguishable from an on-time, fully-completed one, and
	// RunScheduledRecertification's cadence check (recertification.go) would
	// silently treat it as satisfying the FULL cadence window, resetting the
	// clock as if every grant had just been recertified.
	campaign.ForcedIncomplete = force && progress.Pending > 0
	// The "already closed" check above is a plain read, so two concurrent close calls
	// (or a close racing another close) can both observe "open" before either write
	// lands. UpdateAccessReviewCampaign's WHERE-state='open' conditional UPDATE is the
	// actual race-closing guard: ok==false means this call lost the race (the
	// campaign was closed out from under it), so surface the same "already closed"
	// error rather than silently re-closing (and re-stamping ClosedBy/ClosedAt on) an
	// already-frozen evidence record.
	ok, err := c.storage.UpdateAccessReviewCampaign(ctx, campaign)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !ok {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "campaign is already closed")
	}
	c.auditProjectScoped(ctx, EventCampaignClosed, actorID, projectID,
		fmt.Sprintf("closed access-review campaign %d: %d attested, %d revoked, %d pending of %d",
			campaign.ID, progress.Attested, progress.Revoked, progress.Pending, progress.Total))
	return &CampaignWithProgress{Campaign: campaign, Progress: progress}, nil
}
