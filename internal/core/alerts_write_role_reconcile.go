// alerts_write_role_reconcile.go — one-time reconcile for F1 (ADR-110 follow-up,
// Andrei 2026-09-28): seeds the alert_operator built-in role on an install that
// predates it, and grants alerts.write, once, to every role that already holds
// system.write.
//
// system.write's own permission-catalog description has always included "manage
// ... admin job triggers" (auth_bootstrap.go), so every current holder already
// has implicit authority over the alerting surface this splits off — granting
// alerts.write once, at the moment the permission is introduced, does not expand
// what any role can already do. Running this on every startup, though, would
// silently re-grant alerts.write to a role an admin deliberately stripped it from
// after the one-time pass — the same hazard ReconcileUserBaselineRoles documents
// for the baseline-role case (user_baseline_role_reconcile.go, #2195) — so this
// runs exactly once, gated by alertsWriteRoleBackfillMarkerKey.
package core

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/identity"
)

// alertsWriteRoleBackfillMarkerKey is the system_metadata key (ADR-029's
// key/value store, local_system_metadata.go) recording that the one-time
// alerts.write backfill below has already run. Same one-shot-marker pattern as
// userBaselineRoleBackfillMarkerKey (user_baseline_role_reconcile.go, #2195).
const alertsWriteRoleBackfillMarkerKey = "alerts_write_role_backfill_v1"

// ReconcileAlertsWriteRole seeds the alert_operator built-in role (if this
// install was bootstrapped before it existed) and grants alerts.write, once, to
// every role that already holds system.write. Best-effort and non-fatal per
// role, matching ReconcileRBACPermissions' contract; runs exactly once per
// install — see alertsWriteRoleBackfillMarkerKey.
func (c *KeyorixCore) ReconcileAlertsWriteRole(ctx context.Context) error {
	if _, done, err := c.storage.GetSystemMetadata(ctx, alertsWriteRoleBackfillMarkerKey); err != nil {
		return fmt.Errorf("alerts.write role reconcile: check completion marker: %w", err)
	} else if done {
		return nil
	}

	perms, err := c.storage.ListPermissions(ctx)
	if err != nil {
		return fmt.Errorf("alerts.write role reconcile: list permissions: %w", err)
	}
	if len(perms) == 0 {
		return nil // not yet bootstrapped; first-boot seeding owns this — retry next startup
	}
	var systemWriteID, alertsWriteID uint
	for _, p := range perms {
		switch p.Name {
		case "system.write":
			systemWriteID = p.ID
		case permAlertsWrite:
			alertsWriteID = p.ID
		}
	}
	if systemWriteID == 0 || alertsWriteID == 0 {
		// alerts.write not created yet on this install — ReconcileRBACPermissions
		// (rbac_reconcile.go) runs before this in main.go and owns creating it for
		// an already-initialised install; retry next startup once it has.
		return nil
	}

	if err := c.seedAlertOperatorRole(ctx, alertsWriteID); err != nil {
		log.Printf("alerts.write role reconcile: seed alert_operator role: %v", err)
	}

	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return fmt.Errorf("alerts.write role reconcile: list roles: %w", err)
	}

	granted := 0
	for _, role := range roles {
		rolePerms, err := c.storage.GetRolePermissions(ctx, role.ID)
		if err != nil {
			log.Printf("alerts.write role reconcile: list permissions for role %s: %v", role.Name, err)
			continue
		}
		hasSystemWrite, hasAlertsWrite := false, false
		for _, p := range rolePerms {
			switch p.ID {
			case systemWriteID:
				hasSystemWrite = true
			case alertsWriteID:
				hasAlertsWrite = true
			}
		}
		if !hasSystemWrite || hasAlertsWrite {
			continue
		}
		// Routed through the audited core wrapper (actor 0 = system, the same
		// convention ReconcileRBACPermissions uses for its own startup grants) so
		// this backfill emits permission.assigned like every other grant path.
		if err := c.AssignPermissionToRole(ctx, 0, role.ID, alertsWriteID, false); err != nil {
			log.Printf("alerts.write role reconcile: grant alerts.write to role %s: %v", role.Name, err)
			continue
		}
		granted++
	}

	if granted > 0 {
		log.Printf("alerts.write role reconcile: granted alerts.write to %d role(s) already holding system.write", granted)
	}

	if err := c.storage.SetSystemMetadata(ctx, alertsWriteRoleBackfillMarkerKey, "1"); err != nil {
		return fmt.Errorf("alerts.write role reconcile: record completion marker: %w", err)
	}
	return nil
}

// seedAlertOperatorRole creates the "alert_operator" built-in role (alerts.write
// only) if this install predates it. No-op if the role already exists.
// GetRoleByName's error return doubles as its not-found signal (see
// rbac_reconcile.go's identical `err != nil || role == nil` treatment), so any
// error here — not-found or a genuine storage failure — is treated the same
// way: attempt creation, which itself fails loudly (logged by the caller) if the
// storage layer is actually broken.
func (c *KeyorixCore) seedAlertOperatorRole(ctx context.Context, alertsWriteID uint) error {
	if existing, err := c.storage.GetRoleByName(ctx, "alert_operator"); err == nil && existing != nil {
		return nil
	}
	foldedName, err := identity.NewFoldedName("alert_operator")
	if err != nil {
		return fmt.Errorf("normalize alert_operator role name: %w", err)
	}
	role, err := c.storage.CreateRole(ctx, foldedName,
		"Manages notification channels, escalation policies, and on-demand alert/reminder jobs")
	if err != nil {
		return fmt.Errorf("create alert_operator role: %w", err)
	}
	if err := c.storage.AssignPermissionToRole(ctx, role.ID, alertsWriteID); err != nil {
		return fmt.Errorf("assign alerts.write to alert_operator role: %w", err)
	}
	return nil
}
