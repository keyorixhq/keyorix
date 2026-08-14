// access_review_revoke.go — closing the access-recertification loop (ISO 27001
// A.5.18 / SOC 2 CC6.2-6.3). GenerateProjectAccessReview (access_review.go) lists
// who can reach a project's secrets; this file lets a reviewer act on each entry:
//
//   - Revoke  — remove the underlying grant (a role assignment or a share) so the
//     access no longer exists. Audited as access_review.revoked.
//   - Attest  — certify the grant was reviewed and kept. No state change; recorded
//     as access_review.attested so the review itself is evidence of the control.
//
// Both decisions are authoritative recertification actions: the API gates revoke
// behind roles.assign and attest behind roles.read at the project scope. The share
// path deletes the ShareRecord directly (rather than RevokeShare, which requires
// the caller to be the secret owner) because the reviewer acts on the scope's
// authority, not ownership.
package core

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// Access-review decision audit event types.
const (
	EventAccessReviewRevoked  = "access_review.revoked"  // #nosec G101 -- audit event type, not a credential
	EventAccessReviewAttested = "access_review.attested" // #nosec G101 -- audit event type, not a credential
)

// AccessReviewDecision identifies a single access-review entry (a grant of access
// to a project's secrets) for a recertification decision. The fields mirror an
// AccessReviewEntry: Source says which mechanism conferred the grant, and the
// remaining fields point at the specific assignment or share to act on.
//   - Source "role"         → PrincipalType + PrincipalID + RoleID (+ EnvironmentID)
//   - Source "direct_share" → PrincipalID (the user) + SecretID
//   - Source "group_share"  → PrincipalID (the group) + SecretID
type AccessReviewDecision struct {
	Source        string `json:"source"`         // role | direct_share | group_share
	PrincipalType string `json:"principal_type"` // user | group | machine (for role grants)
	PrincipalID   uint   `json:"principal_id"`
	RoleID        uint   `json:"role_id,omitempty"`
	EnvironmentID uint   `json:"environment_id,omitempty"`
	SecretID      uint   `json:"secret_id,omitempty"`
}

// accessReviewAuditDetail is the structured payload stored in a recertification
// event's Diff field, capturing exactly which grant was acted on.
type accessReviewAuditDetail struct {
	Source        string `json:"source"`
	PrincipalType string `json:"principal_type,omitempty"`
	PrincipalID   uint   `json:"principal_id,omitempty"`
	RoleID        uint   `json:"role_id,omitempty"`
	EnvironmentID uint   `json:"environment_id,omitempty"`
	SecretID      uint   `json:"secret_id,omitempty"`
}

// principalTypeForDecision normalizes d's principal type for the reviewer-
// independence check, mirroring GenerateProjectAccessReview's own
// PrincipalType assignment per source (access_review.go): "role" decisions
// carry an explicit, caller-supplied PrincipalType (user/group/machine); the
// other three sources don't (AccessReviewDecision's PrincipalType field is
// documented "for role grants" only) but their principal kind is fixed by
// the source itself — a direct_share/owner principal is always a user, a
// group_share principal is always a group.
func principalTypeForDecision(d AccessReviewDecision) string {
	switch d.Source {
	case "direct_share", "owner":
		return "user"
	case "group_share":
		return "group"
	default: // "role"
		return d.PrincipalType
	}
}

// enforceAccessReviewReviewerControls applies the SAME reviewer-independence
// and human-reviewer controls DecideAccessReviewItem enforces for the
// campaign flow (SOC2 CC6.2-6.3 / ISO A.5.18 / ARC-001) to the standalone
// attest/revoke endpoints (#G52). Before this fix, RevokeAccessReviewGrant/
// AttestAccessReviewGrant had NO such checks at all — DecideAccessReviewItem
// only ever applied them BEFORE calling into these two functions, so a
// caller reaching them directly (project_members.go's standalone HTTP
// handlers) could self-certify their own access, certify access for a group
// they belong to, or have a machine-identity token "review" (attest/revoke)
// with no attributable human reviewer at all.
func (c *KeyorixCore) enforceAccessReviewReviewerControls(ctx context.Context, actorID uint, d AccessReviewDecision) error {
	if err := requireHumanReviewer(actorID); err != nil {
		return err
	}
	principalType := principalTypeForDecision(d)
	if err := c.checkReviewerIndependence(ctx, actorID, principalType, d.PrincipalID); err != nil {
		return err
	}
	// ARC-001: a machine identity provisioned by the actor must not be
	// self-certified by its creator — mirrors DecideAccessReviewItem's
	// identical inline check. Fails closed on a lookup error.
	if d.Source == "role" && principalType == "machine" {
		machine, err := c.storage.GetMachineIdentity(ctx, d.PrincipalID)
		if err != nil {
			return fmt.Errorf("loading machine identity: %w", err)
		}
		if machine.CreatedBy == actorID {
			return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "independent reviewer required for machine identities you provisioned")
		}
	}
	return nil
}

// RevokeAccessReviewGrant removes the grant identified by the decision: a project-
// scoped role assignment (user or group) or a secret share (direct or group). The
// underlying removal is itself audited (role.removed / role.group_removed for
// roles), and a recertification-specific access_review.revoked event records the
// decision with the acting reviewer. actorID is the reviewer performing the revoke.
func (c *KeyorixCore) RevokeAccessReviewGrant(ctx context.Context, actorID, projectID uint, d AccessReviewDecision) error {
	if projectID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if err := c.enforceAccessReviewReviewerControls(ctx, actorID, d); err != nil {
		return err
	}
	switch d.Source {
	case "role":
		if d.PrincipalID == 0 || d.RoleID == 0 {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and role_id are required to revoke a role grant")
		}
		scope := Scope{ProjectID: projectID, EnvironmentID: d.EnvironmentID}
		if err := c.revokeRoleByPrincipalType(ctx, actorID, d, scope); err != nil {
			return err
		}
	case "direct_share", "group_share":
		if d.PrincipalID == 0 || d.SecretID == 0 {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and secret_id are required to revoke a share")
		}
		if err := c.revokeReviewShare(ctx, projectID, d); err != nil {
			return err
		}
	case "owner":
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "ownership cannot be revoked via access review; reassign or delete the secret instead")
	default:
		return fmt.Errorf("%s: unknown access-review source %q", i18n.T("ErrorValidation", nil), d.Source)
	}
	c.logAccessReviewDecision(ctx, EventAccessReviewRevoked, "revoked", actorID, projectID, d)
	return nil
}

func (c *KeyorixCore) revokeRoleByPrincipalType(ctx context.Context, actorID uint, d AccessReviewDecision, scope Scope) error {
	switch d.PrincipalType {
	case "group":
		return c.RemoveRoleFromGroup(ctx, actorID, d.PrincipalID, d.RoleID, scope)
	case "machine":
		return c.RemoveMachineRole(ctx, d.PrincipalID, d.RoleID, scope, actorID)
	default:
		return c.RemoveUserRole(ctx, actorID, d.PrincipalID, d.RoleID, scope)
	}
}

// revokeReviewShare deletes the ShareRecord matching the decision's secret +
// recipient. It deletes the record directly (not via RevokeShare, which is owner-
// gated) because access recertification acts on the project scope's authority —
// which is exactly why the target secret must be verified to belong to THAT
// project first: without it, a reviewer authorized on project A could pass any
// SecretID and delete a share belonging to a secret in a DIFFERENT project
// (IDOR; #99).
func (c *KeyorixCore) revokeReviewShare(ctx context.Context, projectID uint, d AccessReviewDecision) error {
	secret, err := c.storage.GetSecret(ctx, d.SecretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if secret.ProjectID != projectID {
		return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil), "secret does not belong to this project")
	}
	isGroup := d.Source == "group_share"
	shares, err := c.storage.ListSharesBySecret(ctx, d.SecretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, sh := range shares {
		if sh.RecipientID == d.PrincipalID && sh.IsGroup == isGroup {
			if err := c.storage.DeleteShareRecord(ctx, sh.ID); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			return nil
		}
	}
	return fmt.Errorf("%s: no matching share to revoke", i18n.T("ErrorNotFound", nil))
}

// AttestAccessReviewGrant records that the reviewer examined the grant and chose to
// keep it. It changes no state — the access_review.attested event is the evidence
// that the recertification was performed. actorID is the reviewer.
//
// Before recording that evidence, the referenced grant is re-verified against a live
// lookup (mirroring RevokeAccessReviewGrant's validated branches), not just trusted
// from the campaign item's cached snapshot — the grant could have been revoked
// through an unrelated path since the campaign was generated, or the campaign data
// could simply be stale/wrong. An attestation asserts "I reviewed and confirmed this
// access is still needed and correct"; recording it for a grant that no longer exists
// would certify a false state in the compliance evidence trail (#209).
func (c *KeyorixCore) AttestAccessReviewGrant(ctx context.Context, actorID, projectID uint, d AccessReviewDecision) error {
	if projectID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if d.Source == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "source is required")
	}
	if err := c.enforceAccessReviewReviewerControls(ctx, actorID, d); err != nil {
		return err
	}
	if err := c.verifyAccessReviewGrantExists(ctx, projectID, d); err != nil {
		return err
	}
	c.logAccessReviewDecision(ctx, EventAccessReviewAttested, "attested", actorID, projectID, d)
	return nil
}

// verifyAccessReviewGrantExists re-queries the actual grant a decision references —
// the role assignment, share, or ownership row — rather than trusting the decision's
// (possibly stale) fields. Returns a clear "no longer exists, re-sync" error when the
// live lookup finds nothing, mirroring the same real removal calls
// RevokeAccessReviewGrant uses (which likewise fail when the grant is already gone).
func (c *KeyorixCore) verifyAccessReviewGrantExists(ctx context.Context, projectID uint, d AccessReviewDecision) error { // NOSONAR -- cognitive complexity 31, suppress go:S3776
	switch d.Source {
	case "role":
		if d.PrincipalID == 0 || d.RoleID == 0 {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and role_id are required to attest a role grant")
		}
		// #G51: machine-identity role grants live in a separate table from
		// user/group grants (local_rbac.go's MachineIdentityRole vs
		// UserRole/GroupRole) — ListProjectRoleAssignments never queries it,
		// so every machine-identity attestation spuriously "not found" before
		// this branch. RevokeAccessReviewGrant's revokeRoleByPrincipalType
		// already dispatches machine grants separately (RemoveMachineRole);
		// mirror that split here.
		if d.PrincipalType == "machine" {
			machineAssignments, err := c.storage.ListProjectMachineRoleAssignments(ctx, projectID)
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
			}
			for _, a := range machineAssignments {
				if a.PrincipalID == d.PrincipalID && a.RoleID == d.RoleID && a.EnvironmentID == d.EnvironmentID {
					return nil
				}
			}
			return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil),
				"the role grant being attested no longer exists — the review is stale, re-sync and try again")
		}
		assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		wantGroup := d.PrincipalType == "group"
		for _, a := range assignments {
			if (a.PrincipalType == "group") == wantGroup && a.PrincipalID == d.PrincipalID &&
				a.RoleID == d.RoleID && a.EnvironmentID == d.EnvironmentID {
				return nil
			}
		}
		return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil),
			"the role grant being attested no longer exists — the review is stale, re-sync and try again")
	case "direct_share", "group_share":
		if d.PrincipalID == 0 || d.SecretID == 0 {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and secret_id are required to attest a share")
		}
		// #G51: verify the secret actually belongs to projectID BEFORE
		// looking at its shares — otherwise a reviewer authorized on project A
		// could pass any SecretID and attest a share belonging to a secret in
		// a DIFFERENT project (cross-tenant IDOR), certifying compliance
		// evidence for a grant they have no authority over. Mirrors
		// revokeReviewShare's identical guard (#99).
		secret, err := c.storage.GetSecret(ctx, d.SecretID)
		if err != nil || secret == nil || secret.ProjectID != projectID {
			return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil),
				"the share being attested no longer exists — the review is stale, re-sync and try again")
		}
		isGroup := d.Source == "group_share"
		shares, err := c.storage.ListSharesBySecret(ctx, d.SecretID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, sh := range shares {
			if sh.RecipientID == d.PrincipalID && sh.IsGroup == isGroup {
				return nil
			}
		}
		return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil),
			"the share being attested no longer exists — the review is stale, re-sync and try again")
	case "owner":
		if d.PrincipalID == 0 || d.SecretID == 0 {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and secret_id are required to attest ownership")
		}
		secret, err := c.storage.GetSecret(ctx, d.SecretID)
		if err != nil || secret == nil || secret.ProjectID != projectID {
			// #G51: same cross-tenant guard as the share branch above — a
			// secret in a DIFFERENT project must read as "not found" here,
			// not leak whether it exists or who owns it.
			return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil),
				"the secret being attested no longer exists — the review is stale, re-sync and try again")
		}
		if secret.OwnerID != d.PrincipalID {
			return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil),
				"the ownership grant being attested no longer exists — the review is stale, re-sync and try again")
		}
		return nil
	default:
		return fmt.Errorf("%s: unknown access-review source %q", i18n.T("ErrorValidation", nil), d.Source)
	}
}

// logAccessReviewDecision writes the recertification audit event (actor as UserID,
// the secret as SecretNodeID when the grant is per-secret, project as ProjectID,
// and the full decision in the structured diff).
func (c *KeyorixCore) logAccessReviewDecision(ctx context.Context, eventType, verb string, actorID, projectID uint, d AccessReviewDecision) {
	encoded, _ := json.Marshal(accessReviewAuditDetail(d))
	var actor *uint
	if actorID != 0 {
		a := actorID
		actor = &a
	}
	var secretID *uint
	if d.SecretID != 0 {
		s := d.SecretID
		secretID = &s
	}
	pid := projectID
	principal := d.PrincipalType
	if principal == "" {
		principal = "principal"
	}
	desc := fmt.Sprintf("access review: %s %s grant for %s %d", verb, d.Source, principal, d.PrincipalID)
	c.writeAuditEventDiff(ctx, eventType, actor, secretID, &pid, "", desc, string(encoded))
}
