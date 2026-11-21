package main

import (
	"context"
	"errors"
	"log"
	"time"
)

// wireRBACPermissionCatalog is a core wiring step (coreWiringSteps in main.go).
func wireRBACPermissionCatalog(cw *coreWiring) error {
	coreService := cw.core
	// Top up the canonical RBAC permission catalog (ADR-044): adds any permission
	// introduced in a later release to an already-initialised install, granting it to
	// its baseline roles. No-op pre-bootstrap and best-effort (never blocks startup).
	// The run holds a named lock, so it can wait behind another replica's run; the
	// timeout keeps that wait bounded (REVIEW-4560 L2). A run cut off before its
	// grants leaves its debt for the next startup; one cut off mid-grant drops and
	// logs the pairs it could not grant (fail closed, never a re-grant).
	ctx, cancel := context.WithTimeout(context.Background(), rbacReconcileTimeout)
	defer cancel()
	if err := coreService.ReconcileRBACPermissions(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Printf("RBAC permission reconciliation: not finished within %s (another replica may hold its lock); retried next startup (continuing)", rbacReconcileTimeout)
		} else {
			log.Printf("RBAC permission reconciliation: %v (continuing)", err)
		}
	}
	return nil
}

// rbacReconcileTimeout bounds wireRBACPermissionCatalog, including the wait for
// the reconcile's named lock.
const rbacReconcileTimeout = 2 * time.Minute

// wireAlertsWriteRole is a core wiring step (coreWiringSteps in main.go).
func wireAlertsWriteRole(cw *coreWiring) error {
	coreService := cw.core
	// F1 (ADR-110 follow-up): seed the alert_operator built-in role on an
	// install that predates it, and grant alerts.write, once, to every role that
	// already holds system.write. No-op pre-bootstrap and best-effort (never
	// blocks startup); a no-op on every subsequent restart once run.
	if err := coreService.ReconcileAlertsWriteRole(context.Background()); err != nil {
		log.Printf("alerts.write role reconciliation: %v (continuing)", err)
	}
	return nil
}
