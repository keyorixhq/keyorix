// access_review_decide_tx.go — #2676: a campaign revoke decision claims the
// item, removes the grant, and records its evidence in ONE transaction.
//
// Why this could not just be reordered the way the attest half was
// ------------------------------------------------------------------
// #2570 fixed the attest half by moving its work (which is all reads) ahead of
// the claim, so a reported error always means the item is still pending. A
// revoke cannot do that: claim-before-act is precisely what closes #1646's
// cross-replica race (two replicas racing an attest against a revoke on the
// same item could otherwise both read Decision==pending and both act, letting a
// revoked grant persist as "attested"). The revoke genuinely has to act AFTER
// its claim has committed — unless the claim and the act commit together.
//
// What the gap actually was
// -------------------------
// If the grant removal failed after the claim committed, the item stayed
// stamped `revoked` while the grant was still live, and DecideAccessReviewItem
// logged "SECURITY: ... manual reconciliation required" and returned the error.
// Two consequences, both bad for a control whose entire output is evidence:
//
//   - False compliance record. An auditor reading the campaign sees "access
//     revoked, by this reviewer, at this time" for access that still exists
//     (ISO 27001 A.5.18 / SOC 2 CC6.2-6.3).
//   - Not retryable. The item was no longer pending, so the reviewer who had
//     just been told the action failed could not perform it: the next attempt
//     is refused with "this item has already been decided".
//
// It did not need fault injection to reach, either: a last-project-admin guard
// REFUSAL — an ordinary, expected outcome — took the same path, stamping the
// item `revoked` for a removal the system had deliberately declined to make.
// That is the case the regression tests lead with
// (access_review_decide_atomicity_test.go).
//
// Lock ordering: named lock OUTSIDE, transaction INSIDE
// -----------------------------------------------------
// Every guarded removal path takes a named lock (LocalStorage.WithNamedLock: a
// per-key process mutex, plus a session-scoped pg_advisory_lock on its own
// pooled connection for Postgres/HA). This code acquires that lock FIRST and
// opens the transaction inside it, never the reverse. The reverse inverts: a
// transaction holding the claim's row lock would then wait on an advisory lock
// whose holder may be waiting on that same row.
//
// Acquiring it outside is also the ordering the rest of this package already
// uses — removeGlobalAdminRoleIfApplicable's doc comment records the same
// named-lock-then-inner-work rule, and for the same reason. The guard's READS
// stay where RemoveUserRole/RemoveRoleFromGroup already put them (inside the
// lock, before the write), so the lock still spans read-guard-write exactly as
// #1646 requires; the only change is that the write now shares a transaction
// with the claim and the audit row.
//
// Connection budget: this chain needs TWO pooled connections at once
// -------------------------------------------------------------------
// The named lock holds one (pg_advisory_lock is session-scoped, so
// WithNamedLock keeps its own *sql.Conn for the whole closure) and the
// transaction holds a second. Nothing inside the transaction may ask the pool
// for a THIRD — every read and write in there must go through the tx handle,
// never c.storage. A stray c.storage read deadlocks outright rather than
// degrading: database/sql blocks forever waiting for a connection this same
// chain is holding.
//
// This is not hypothetical. claimItemDecision's lost-race re-read was left on
// c.storage when it was given a storage-handle parameter, and the result was a
// 120-second hang whose goroutine dump showed exactly this shape —
// GetAccessReviewItem parked in database/sql.(*DB).conn inside
// WithTransaction inside WithNamedLock. internal/core's Postgres contention
// helpers open with MaxOpenConns(2) (postgres_contention_helpers_test.go) and
// internal/config enforces no minimum above that, so two IS the budget, not a
// safety margin.
//
// Two-not-one is a real cost: namedLockConnCtxKey's doc comment records the
// work done to make a lock chain need only ONE connection no matter how many
// keys it nests, and a transaction nested inside takes that back. The
// alternative — pg_advisory_xact_lock taken on the transaction's own
// connection, one connection total — requires every guard's reads to move
// inside the transaction, which means threading a storage handle through
// guardLastProjectAdmin, guardLastProjectAdminGroupRole,
// resolveGlobalAdminHolders, filterActiveHolders and adminBypassRoleIDSet, and
// changes those guards' read isolation. Not worth it for a two-connection
// ceiling that is pinned by a test:
// TestConcurrency_DecideAccessReviewRevoke_Postgres_NamedLockOutsideTransactionDoesNotDeadlock
// runs this path against real Postgres through pgOpen's MaxOpenConns(2), so a
// future third connection need fails there rather than in production.
//
// Guard and lock are NOT restated here. withUserRoleRemovalGuards /
// withGroupRoleRemovalGuards / withMachineRoleRemovalGuards are the same
// wrappers the public removal methods go through — one source of truth, two
// writes. A copy of "which lock, which guard, at which scope" is the
// separately-maintained-second-implementation shape #2496 had to unwind, and
// here it would be load-bearing for the last-admin invariant.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// reviewRevokeApply is one grant-removal plan: the already-resolved guard
// wrapper to run it under, the transactional write itself, and the process-local
// side effect to run only after the transaction commits.
type reviewRevokeApply struct {
	// guarded wraps write in the named lock and last-admin guard this removal
	// requires. Always one of the with*RemovalGuards helpers — never a local
	// re-derivation.
	guarded func(ctx context.Context, write func(ctx context.Context) error) error
	// write performs the removal and its own audit event through the
	// transaction-scoped handles.
	write func(ctx context.Context, tx storage.Storage, tgt auditTarget) error
	// afterCommit runs process-local side effects (auth-cache eviction) that
	// have no transaction to belong to and must not happen on rollback. nil when
	// there are none.
	afterCommit func(ctx context.Context)
}

// planReviewRevoke resolves the decision into a removal plan, running every
// pre-flight validation RevokeAccessReviewGrant performs for the same decision —
// reviewer controls included — so this path and the standalone endpoint accept
// and reject exactly the same requests.
func (c *KeyorixCore) planReviewRevoke(ctx context.Context, actorID, projectID uint, d AccessReviewDecision) (*reviewRevokeApply, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if err := c.enforceAccessReviewReviewerControls(ctx, actorID, d); err != nil {
		return nil, err
	}
	switch d.Source {
	case "role":
		if d.PrincipalID == 0 || d.RoleID == 0 {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and role_id are required to revoke a role grant")
		}
		return c.planReviewRoleRevoke(ctx, actorID, projectID, d)
	case "direct_share", "group_share":
		if d.PrincipalID == 0 || d.SecretID == 0 {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "principal_id and secret_id are required to revoke a share")
		}
		return &reviewRevokeApply{
			guarded: runUnguarded,
			write: func(ctx context.Context, tx storage.Storage, _ auditTarget) error {
				return c.revokeReviewShareOn(ctx, tx, projectID, d)
			},
		}, nil
	case "owner":
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "ownership cannot be revoked via access review; reassign or delete the secret instead")
	default:
		return nil, fmt.Errorf("%s: unknown access-review source %q", i18n.T("ErrorValidation", nil), d.Source)
	}
}

// planReviewRoleRevoke resolves a role-grant revoke per principal kind, mirroring
// revokeRoleByPrincipalType's dispatch.
func (c *KeyorixCore) planReviewRoleRevoke(ctx context.Context, actorID, projectID uint, d AccessReviewDecision) (*reviewRevokeApply, error) {
	scope := Scope{ProjectID: projectID, EnvironmentID: d.EnvironmentID}
	switch d.PrincipalType {
	case "group":
		if _, err := c.storage.GetGroup(ctx, d.PrincipalID); err != nil {
			return nil, fmt.Errorf("group not found: %w", err)
		}
		return &reviewRevokeApply{
			guarded: func(ctx context.Context, write func(ctx context.Context) error) error {
				return c.withGroupRoleRemovalGuards(ctx, d.PrincipalID, d.RoleID, scope, write)
			},
			write: func(ctx context.Context, tx storage.Storage, tgt auditTarget) error {
				return c.removeGroupRoleWriteOn(ctx, tx, tgt, actorID, d.PrincipalID, d.RoleID, scope)
			},
		}, nil
	case "machine":
		m, err := c.machineInProject(ctx, scope.ProjectID, d.PrincipalID)
		if err != nil {
			return nil, err
		}
		return &reviewRevokeApply{
			guarded: func(ctx context.Context, write func(ctx context.Context) error) error {
				return c.withMachineRoleRemovalGuards(ctx, d.PrincipalID, scope, write)
			},
			write: func(ctx context.Context, tx storage.Storage, tgt auditTarget) error {
				return c.removeMachineRoleWriteOn(ctx, tx, tgt, m, d.RoleID, scope, actorID)
			},
		}, nil
	default:
		return &reviewRevokeApply{
			guarded: func(ctx context.Context, write func(ctx context.Context) error) error {
				return c.withUserRoleRemovalGuards(ctx, d.PrincipalID, d.RoleID, scope, write)
			},
			write: func(ctx context.Context, tx storage.Storage, tgt auditTarget) error {
				return c.removeUserRoleWriteOn(ctx, tx, tgt, actorID, d.PrincipalID, d.RoleID, scope)
			},
			// RemoveUserRole evicts the subject's auth cache so a just-revoked
			// role stops authorizing on the very next request. Deferred past the
			// commit: evicting before it would let a concurrent request re-cache
			// the pre-removal snapshot and keep serving it for the rest of the
			// positive-cache TTL.
			afterCommit: func(ctx context.Context) { c.evictUserSessionCache(ctx, d.PrincipalID) },
		}, nil
	}
}

// runUnguarded is the guarded-wrapper for a removal that needs no named lock or
// last-admin guard (a share deletion). Named rather than inlined as nil so every
// plan has a wrapper and the caller needs no nil check — "no guard" is then a
// stated property of the plan, not an absent field.
func runUnguarded(ctx context.Context, write func(ctx context.Context) error) error {
	return write(ctx)
}

// revokeReviewShareOn is revokeReviewShare through an explicit storage handle.
// Both its reads (the cross-project ownership check #99 closes, and the share
// lookup) and its delete go through tx, so the share it resolves is the share it
// deletes — strictly tighter than resolving outside the transaction.
func (c *KeyorixCore) revokeReviewShareOn(ctx context.Context, st storage.Storage, projectID uint, d AccessReviewDecision) error {
	secret, err := st.GetSecret(ctx, d.SecretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if secret.ProjectID != projectID {
		return fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil), "secret does not belong to this project")
	}
	isGroup := d.Source == "group_share"
	shares, err := st.ListSharesBySecret(ctx, d.SecretID, c.shareEffectiveNow())
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, sh := range shares {
		if sh.RecipientID == d.PrincipalID && sh.IsGroup == isGroup {
			if err := st.DeleteShareRecord(ctx, sh.ID); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
			return nil
		}
	}
	return fmt.Errorf("%s: no matching share to revoke", i18n.T("ErrorNotFound", nil))
}

// decideReviewItemRevokeAtomically claims the item, removes the grant and writes
// both audit events in one transaction. A failure anywhere — the storage delete,
// the last-admin guard, the claim losing its race — leaves NOTHING behind: the
// item stays pending, the grant stays, no evidence is recorded, and the reviewer
// can retry.
//
// The claim's own cross-replica guarantee is unchanged and, if anything,
// stronger: claimItemDecision's conditional UPDATE (WHERE decision='pending')
// is still what decides the race, and running it inside the transaction means
// the losing replica's identical UPDATE blocks on the row until this one commits
// or rolls back, rather than racing a committed-but-unapplied claim.
func (c *KeyorixCore) decideReviewItemRevokeAtomically(ctx context.Context, actorID, projectID uint, item *models.AccessReviewItem, itemID uint, reason string, d AccessReviewDecision) error {
	plan, err := c.planReviewRevoke(ctx, actorID, projectID, d)
	if err != nil {
		return err
	}
	return plan.guarded(ctx, func(lockCtx context.Context) error {
		sink := &auditForwardSink{}
		if err := c.storage.WithTransaction(lockCtx, func(tx storage.Storage) error {
			tgt := auditInto(tx, sink)
			if err := c.claimItemDecisionOn(lockCtx, tx, item, itemID, actorID, ReviewItemRevoked, reason); err != nil {
				return err
			}
			if err := plan.write(lockCtx, tx, tgt); err != nil {
				return err
			}
			c.logAccessReviewDecisionOn(lockCtx, tgt, EventAccessReviewRevoked, "revoked", actorID, projectID, d)
			return nil
		}); err != nil {
			// No "manual reconciliation required" log here, unlike the
			// pre-#2676 code: there is nothing to reconcile. The claim rolled
			// back with the removal, so the item is pending and the decision is
			// simply retryable.
			return err
		}
		// Only now that the transaction committed: forward the audit events
		// off-box and evict the subject's auth cache.
		sink.Flush(c)
		if plan.afterCommit != nil {
			plan.afterCommit(lockCtx)
		}
		return nil
	})
}
