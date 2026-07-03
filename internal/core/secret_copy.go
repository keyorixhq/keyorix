// secret_copy.go — copy a secret's current value and metadata into another environment
// of the same project (e.g. promote staging → production). The copy is a brand-new,
// independently-owned secret (owned by the copier, fresh version 1) — not a link, so
// the two diverge from then on. Reading the source value is permission-checked here;
// creating in the target environment is authorized by the caller (transport). Staying
// within one project prevents a cross-project value exfiltration via copy.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CopySecret creates a new secret in targetEnvID with the source secret's value and
// metadata (type, classification, description). newName defaults to the source name
// when empty. The actor must be able to read the source (enforced here) and — checked
// by the transport — to create in the target environment. The target environment must
// belong to the same project as the source. Records the source read and the
// destination create in the audit trail (audit_events + secret_access_logs, #126/#290)
// — CreateSecret alone leaves no trace that a copy also read the source value, and
// GetSecretValueWithPermissionCheck's max-reads accounting is not an audit event —
// without this, a copy was a covert exfil channel invisible to the anomaly detector
// (which keys off SecretAccessLog rows the Log* helpers write). ip/ua attribute the
// events (pass-through from the request); empty is tolerated.
func (c *KeyorixCore) CopySecret(ctx context.Context, sourceID, targetEnvID uint, newName, actorUsername string, actorID uint, ip, ua string) (*models.SecretNode, error) {
	if sourceID == 0 || targetEnvID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "source secret ID and target environment ID are required")
	}

	source, err := c.GetSecret(ctx, sourceID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Same-project guard: the target environment must live in the source's project,
	// so a copy can never move a value across a project boundary.
	targetEnv, err := c.storage.GetEnvironment(ctx, targetEnvID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if targetEnv.ProjectID != source.ProjectID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "target environment must be in the same project as the source")
	}

	// Read the source value — permission-checked (the actor must be able to read it).
	value, err := c.GetSecretValueWithPermissionCheck(ctx, sourceID, actorID)
	if err != nil {
		return nil, err
	}
	c.LogSecretReadWithProject(ctx, actorID, source.ID, source.ProjectID, actorUsername, source.Name, ip, ua)

	name := strings.TrimSpace(newName)
	if name == "" {
		name = source.Name
	}

	// CreateSecret re-validates the value policy, the env↔project link, and name
	// uniqueness within the target environment.
	created, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name:           name,
		Value:          value,
		ProjectID:      source.ProjectID,
		EnvironmentID:  targetEnvID,
		Type:           source.Type,
		Classification: source.Classification,
		Description:    source.Description,
		CreatedBy:      actorUsername,
		OwnerID:        actorID,
	})
	if err != nil {
		return nil, err
	}
	c.LogSecretCreatedWithProject(ctx, actorID, created.ID, source.ProjectID, actorUsername, created.Name, ip, ua)
	return created, nil
}
