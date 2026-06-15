// machine_identities.go — non-human project identities and their lifecycle (ADR-023).
//
// A machine identity (CI runner, k8s workload, service, automation) is a
// first-class project member kept separate from human users so the Members view
// can segment the two. Lifecycle is a 4-state machine:
//
//	pending → active → suspended ⇄ active        (revoked is terminal, reachable
//	                                              from any non-revoked state)
//
// `pending` is the credential-awaiting state for the (future) machine-token
// issuance flow; identities created today start `active`. Every transition is
// audited. Machine-token authentication itself is a deliberate follow-up.
package core

import (
	"context"
	"fmt"

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

// TransitionMachineIdentity advances a machine identity to a new state,
// enforcing the state machine, and audits the change. The machine must belong to
// projectID — the caller's authorization is scoped to that project, so a machine
// in another project must not be reachable through it (cross-project guard).
func (c *KeyorixCore) TransitionMachineIdentity(ctx context.Context, projectID, id uint, to string, actorID uint) (*models.MachineIdentity, error) {
	m, err := c.machineInProject(ctx, projectID, id)
	if err != nil {
		return nil, err
	}
	if !canTransitionMachine(m.State, to) {
		return nil, fmt.Errorf("cannot transition machine identity from %s to %s", m.State, to)
	}
	now := c.now()
	m.State = to
	m.UpdatedAt = now
	if to == MachineRevoked {
		m.RevokedAt = &now
	}
	if err := c.storage.UpdateMachineIdentity(ctx, m); err != nil {
		return nil, fmt.Errorf("failed to update machine identity: %w", err)
	}
	c.logMachineEvent(ctx, "machine_identity."+machineVerb(to), m, actorID)
	return m, nil
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
