package core

import (
	"context"
	"sync"
	"time"

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
