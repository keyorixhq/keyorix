// machine_identities.go — non-human project identities and their lifecycle (ADR-023).
//
// A machine identity (CI runner, k8s workload, service, automation) is a
// first-class project member kept separate from human users so the Members view
// can segment the two. Lifecycle is a 4-state machine:
//
//	pending → active → suspended ⇄ active        (revoked is terminal, reachable
//	                                              from any non-revoked state)
//
// `pending` is the credential-awaiting state for the machine-token issuance
// flow (ADR-030, see machine_token.go); identities created today start
// `active`. Every transition is audited. Machine-token issuance, hashing,
// revocation, and validation are fully implemented and wired into both the
// HTTP and gRPC auth middleware.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Machine identity types.
const (
	MachineTypeCI         = "ci"
	MachineTypeK8s        = "k8s"
	MachineTypeService    = "service"
	MachineTypeAutomation = "automation"
	MachineTypeOther      = "other"
)

var validMachineTypes = map[string]struct{}{
	MachineTypeCI: {}, MachineTypeK8s: {}, MachineTypeService: {},
	MachineTypeAutomation: {}, MachineTypeOther: {},
}

// Machine identity states.
const (
	MachinePending   = "pending"
	MachineActive    = "active"
	MachineSuspended = "suspended"
	MachineRevoked   = "revoked"
)

// machineTransitions lists allowed next states. revoked is terminal.
var machineTransitions = map[string][]string{
	MachinePending:   {MachineActive, MachineRevoked},
	MachineActive:    {MachineSuspended, MachineRevoked},
	MachineSuspended: {MachineActive, MachineRevoked},
	MachineRevoked:   {},
}

func canTransitionMachine(from, to string) bool {
	for _, next := range machineTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// CreateMachineIdentity creates an active machine identity in a project.
func (c *KeyorixCore) CreateMachineIdentity(ctx context.Context, projectID uint, name, identityType, description, classification string, createdBy uint) (*models.MachineIdentity, error) {
	if projectID == 0 || name == "" {
		return nil, fmt.Errorf("project ID and name are required")
	}
	if identityType == "" {
		identityType = MachineTypeOther
	}
	if _, ok := validMachineTypes[identityType]; !ok {
		return nil, fmt.Errorf("invalid identity_type %q (want ci|k8s|service|automation|other)", identityType)
	}
	if !IsValidClassification(classification) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	now := c.now()
	m := &models.MachineIdentity{
		ProjectID:      projectID,
		Name:           name,
		IdentityType:   identityType,
		State:          MachineActive,
		Description:    description,
		Classification: classification,
		CreatedBy:      createdBy,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	created, err := c.storage.CreateMachineIdentity(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("failed to create machine identity: %w", err)
	}
	c.logMachineEvent(ctx, "machine_identity.created", created, createdBy)
	return created, nil
}

// ListMachineIdentities returns the machine identities in a project.
func (c *KeyorixCore) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	return c.storage.ListMachineIdentities(ctx, projectID)
}

// ListStaleMachineIdentities returns a project's ACTIVE machine identities that have
// not authenticated within olderThan — abandoned credentials that are candidates for
// revocation (a security-hygiene aid). An identity that has never been seen counts
// from its creation time, so a freshly-created one isn't flagged until it has had the
// full window to be used. Suspended/revoked identities are excluded (already handled).
func (c *KeyorixCore) ListStaleMachineIdentities(ctx context.Context, projectID uint, olderThan time.Duration) ([]*models.MachineIdentity, error) {
	all, err := c.storage.ListMachineIdentities(ctx, projectID)
	if err != nil {
		return nil, err
	}
	cutoff := c.now().Add(-olderThan)
	var stale []*models.MachineIdentity
	for _, m := range all {
		if m.State != MachineActive {
			continue
		}
		last := m.CreatedAt
		if m.LastSeenAt != nil {
			last = *m.LastSeenAt
		}
		if last.Before(cutoff) {
			stale = append(stale, m)
		}
	}
	return stale, nil
}

// TransitionMachineIdentity advances a machine identity to a new state,
// enforcing the state machine, and audits the change. The machine must belong to
// projectID — the caller's authorization is scoped to that project, so a machine
// in another project must not be reachable through it (cross-project guard).
//
// #388: the read-check-write is done inside a transaction against a row obtained via
// LockMachineIdentityForUpdate, not a plain GetMachineIdentity — without a DB-level
// guard, two concurrent transitions racing off the same pre-transition state (e.g.
// one to revoked, one racing back to active from suspended) can each independently
// pass canTransitionMachine, and whichever write landed last would silently win
// outright, un-revoking a just-revoked machine identity. The row lock (Postgres:
// SELECT ... FOR UPDATE) serializes this across replicas; the transaction alone
// serializes it on SQLite (always single-process).
//
// Finding #518: the actual write goes through TransitionMachineIdentityState, a
// conditional "WHERE id = ? AND state = ?" persist, rather than a plain
// UpdateMachineIdentity — because storage.type: remote's RemoteStorage.WithTransaction
// is a no-op passthrough over HTTP (no real transaction/row-lock spans the Lock
// call and the write), a plain Lock-then-Update proxy pair would silently lose the
// #388 guarantee entirely under remote mode. Gating the write itself on the state
// this call observed under the lock restores the guarantee across that HTTP hop:
// a lost race reports matched=false, treated identically to an illegal transition.
// This makes no behavioral difference against LocalStorage (the lock already
// guarantees the state can't have moved by the time the conditional write runs).
// transitionMachineInTx performs the state transition inside an existing transaction.
// It is the body of TransitionMachineIdentity's WithTransaction closure, extracted to
// keep the outer function's cognitive complexity within limits.
func (c *KeyorixCore) transitionMachineInTx(ctx context.Context, tx storage.Storage, projectID, id uint, to string, now time.Time) (*models.MachineIdentity, error) {
	m, err := tx.LockMachineIdentityForUpdate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("machine identity not found")
	}
	if m.ProjectID != projectID {
		// Cross-project guard: report as "not found" (not a permission error) to
		// avoid confirming the machine's existence to a caller scoped elsewhere.
		return nil, fmt.Errorf("machine identity not found")
	}
	fromState := m.State
	if !canTransitionMachine(fromState, to) {
		return nil, fmt.Errorf("cannot transition machine identity from %s to %s", fromState, to)
	}
	m.State = to
	m.UpdatedAt = now
	if to == MachineRevoked {
		m.RevokedAt = &now
	}
	matched, err := tx.TransitionMachineIdentityState(ctx, m, fromState)
	if err != nil {
		return nil, fmt.Errorf("failed to update machine identity: %w", err)
	}
	if !matched {
		// Lost the race: the row's persisted state moved away from fromState
		// between the lock read and this write (#388) — treat exactly like an
		// illegal transition rather than silently overwriting the winner.
		return nil, fmt.Errorf("cannot transition machine identity from %s to %s", fromState, to)
	}
	return m, nil
}

func (c *KeyorixCore) TransitionMachineIdentity(ctx context.Context, projectID, id uint, to string, actorID uint) (*models.MachineIdentity, error) {
	now := c.now()
	var result *models.MachineIdentity
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var err error
		result, err = c.transitionMachineInTx(ctx, tx, projectID, id, to, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	// Suspend or revoke must evict every credential from the auth cache
	// immediately so the identity stops authenticating on the next HTTP request
	// rather than after validTokenTTL (30s). The HTTP handler also calls
	// InvalidateTokenCacheByHash directly (defence-in-depth); this call moves
	// the eviction into the core so gRPC callers (which have no HTTP middleware
	// reference) get the same guarantee automatically (#r124).
	if to == MachineSuspended || to == MachineRevoked {
		if hashes, herr := c.MachineTokenHashes(ctx, id); herr == nil {
			c.invalidateTokenCache(hashes...)
		}
	}
	c.logMachineEvent(ctx, "machine_identity."+machineVerb(to), result, actorID)
	return result, nil
}

// ClassifyMachineIdentity sets (or clears, with "") the data-classification label
// on a machine identity, project-scoped (cross-project guard), and audits the change.
func (c *KeyorixCore) ClassifyMachineIdentity(ctx context.Context, projectID, id uint, level string, actorID uint) (*models.MachineIdentity, error) {
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	m, err := c.machineInProject(ctx, projectID, id)
	if err != nil {
		return nil, err
	}
	if m.Classification == level {
		return m, nil // no-op
	}
	old := m.Classification
	m.Classification = level
	m.UpdatedAt = c.now()
	if err := c.storage.UpdateMachineIdentity(ctx, m); err != nil {
		return nil, fmt.Errorf("failed to update machine identity: %w", err)
	}
	aid, pid := actorID, m.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "machine_identity.classified", &aid, nil, &pid, "",
		fmt.Sprintf("machine identity %d (%s) classification set to %q", m.ID, m.Name, level), diff)
	return m, nil
}

func machineVerb(to string) string {
	switch to {
	case MachineActive:
		return "activated"
	case MachineSuspended:
		return "suspended"
	case MachineRevoked:
		return "revoked"
	default:
		return to
	}
}

func (c *KeyorixCore) logMachineEvent(ctx context.Context, eventType string, m *models.MachineIdentity, actorID uint) {
	aid, pid := actorID, m.ProjectID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, &pid, "",
		fmt.Sprintf("machine identity %q (%s) in project %d → %s", m.Name, m.IdentityType, m.ProjectID, m.State))
}
