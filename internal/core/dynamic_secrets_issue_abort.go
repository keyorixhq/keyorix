package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// abortedIssueCleanupTimeout bounds the revoke and the lease write of cleanupAbortedIssue,
// which run on a context detached from the (possibly already expired) request.
const abortedIssueCleanupTimeout = 30 * time.Second

// withIssuedRoleCapture returns a context for engine.Issue that records the account name
// the engine reports before its first target write (ports.ReportIssuedRole), and a getter
// for it ("" when the engine never reported one: cloud engines, test doubles).
func withIssuedRoleCapture(ctx context.Context) (context.Context, func() string) {
	var (
		mu   sync.Mutex
		name string
	)
	ctx = ports.WithIssuedRoleReporter(ctx, func(roleName string) {
		mu.Lock()
		defer mu.Unlock()
		name = roleName
	})
	return ctx, func() string {
		mu.Lock()
		defer mu.Unlock()
		return name
	}
}

// cleanupAbortedIssue handles an Issue that failed after the engine named its account.
// Core cannot tell whether the target created it (the panic or the reset may have come
// before or after), so it revokes by name: every database engine's Revoke is idempotent
// (DROP ... IF EXISTS, dropUser tolerating "not found", ACL DELUSER of a missing user).
// A revoke that fails leaves a revoke_failed lease row, which the sweep and the manual
// retry both pick up, plus the audit event cleanupOrphanedRole writes. It runs detached
// from ctx's cancellation: a timeout is one of the reasons Issue fails, and must not stop
// the cleanup that follows it.
func (c *KeyorixCore) cleanupAbortedIssue(ctx context.Context, cfg *models.DynamicSecretConfig, engine ports.DynamicBackendEngine, adminDSN, roleName string, userID uint) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortedIssueCleanupTimeout)
	defer cancel()
	c.cleanupOrphanedRole(cctx, cfg, engine, adminDSN, roleName, userID)
}

// abortUnauditedLease handles an IssueLease whose dynamic_lease.issued event was not
// committed (#4716): the credential must not be returned, so the minted role is revoked
// through cleanupOrphanedRole's body, revokeOrRecordOrphan (which records a revoke_failed row and its audit event if
// the revoke fails) and the already persisted lease row, which would otherwise stay
// `active` for a credential nobody received, is marked revoked, or revoke_failed when the
// role is still live. Detached from ctx's cancellation like cleanupAbortedIssue.
func (c *KeyorixCore) abortUnauditedLease(ctx context.Context, cfg *models.DynamicSecretConfig, engine ports.DynamicBackendEngine, adminDSN string, lease *models.DynamicSecretLease, userID uint) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortedIssueCleanupTimeout)
	defer cancel()
	status, reason, revokeErr := "revoked", "audit_unavailable", ""
	if !c.revokeOrRecordOrphan(cctx, cfg, engine, adminDSN, lease.RoleName, userID) {
		status, reason = "revoke_failed", ""
		revokeErr = "issue aborted: the audit event could not be written and the role could not be revoked — see the orphaned lease row for this role"
	}
	now := c.now()
	var revokedAt *time.Time
	if status == "revoked" {
		revokedAt = &now // revoke_failed stays unstamped, as in RevokeLease: the role is still live
	}
	besteffort.Run(cctx, "dynamic_secrets.abortUnauditedLease.RecordDynamicSecretLeaseRevocation", func() error {
		matched, err := c.storage.RecordDynamicSecretLeaseRevocation(cctx, lease.LeaseID, status, reason, revokeErr, revokedAt)
		if err == nil && !matched {
			return fmt.Errorf("lease %s: no row matched while closing an unaudited issue", lease.LeaseID)
		}
		return err
	})
}
