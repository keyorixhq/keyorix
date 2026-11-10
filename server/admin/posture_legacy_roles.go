package admin

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// legacyRoleGrantLister is the part of core the legacy-role check reads.
type legacyRoleGrantLister interface {
	ListLegacyRoleProjectGrants(ctx context.Context) ([]core.LegacyRoleProjectGrant, error)
	ListPendingInvitationsOutsideAssignableScope(ctx context.Context) ([]core.InvitationOutsideScope, error)
}

// collectLegacyRoleGrantsPosture is the upgrade check for #3605: it names every
// existing per-project grant of a legacy role and how to replace it, plus the
// pending invitations that can no longer be accepted. These are warnings, never
// deviations: the grants keep working, so they must not fail the command. A
// failed read is a deviation, so the check cannot silently report nothing, and
// so is a legacy break-glass emergency role, which is broken rather than
// merely due for replacement: it refuses every activation.
func collectLegacyRoleGrantsPosture(ctx context.Context, cfg *config.Config, lister legacyRoleGrantLister, report *postureReport) {
	if cfg.BreakGlass.Enabled {
		if line := core.LegacyEmergencyRoleWarning(cfg.BreakGlass.EmergencyRole); line != "" {
			report.deviate("legacy-role-grants", line)
		}
	}
	grants, err := lister.ListLegacyRoleProjectGrants(ctx)
	if err != nil {
		report.deviate("legacy-role-grants", fmt.Sprintf("posture check could not list per-project grants of legacy roles, so that check was NOT evaluated: %v", err))
		return
	}
	for _, line := range core.LegacyRoleProjectGrantReport(grants, 0) {
		report.warn(line)
	}
	invitations, err := lister.ListPendingInvitationsOutsideAssignableScope(ctx)
	if err != nil {
		report.deviate("legacy-role-grants", fmt.Sprintf("posture check could not list pending invitations, so the legacy role invitation check was NOT evaluated: %v", err))
		return
	}
	for _, inv := range invitations {
		if replacement, ok := models.LegacyRoleProjectReplacement(inv.RoleName); ok && inv.ProjectID != 0 {
			report.warn(fmt.Sprintf("invitation %d (%s) grants %s at project_id=%d, so accepting it now fails: revoke it and invite with %s instead",
				inv.InvitationID, inv.Email, inv.RoleName, inv.ProjectID, replacement))
		}
	}
}
