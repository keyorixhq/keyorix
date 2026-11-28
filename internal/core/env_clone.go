// env_clone.go — CloneEnvironment: copy every active secret from one environment
// into another within the same project (staging → production promotion). Secrets
// that already exist by name in the destination are skipped; only the latest
// version of each source secret is copied.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const cloneEnvPageSize = 500

// EventEnvironmentCloneStarted is written before CloneEnvironment copies anything
// (fail-closed, #4718); environment.cloned summarises the run afterwards.
const EventEnvironmentCloneStarted = "environment.clone_started"

// EnvCloneResult summarises the outcome of a CloneEnvironment call.
type EnvCloneResult struct {
	SourceEnv      string
	DestEnv        string
	SecretsCloned  int
	SecretsSkipped int // secrets that already exist in dest (skipped, not overwritten)
	Errors         []string
}

// cloneEnvironmentReadError classifies a failed read of one of the two environments a
// clone names. A positive not-found keeps its worded refusal ("Validation error: source
// environment: environment not found", the text clients and the 404 mapping know) and
// matches storage.ErrEnvironmentNotFound; any other failure is a storage read fault
// (ErrStorageReadUnavailable), never worded as a refused input.
func cloneEnvironmentReadError(which string, err error) error {
	if !isPositiveNotFound(err) {
		return &storageReadFault{cause: err}
	}
	return refuseAs(storage.ErrEnvironmentNotFound, fmt.Errorf("%s: %s: %w", i18n.T("ErrorValidation", nil), which, err))
}

// CloneEnvironment copies all active secrets from srcEnvID to dstEnvID.
// Both environments must belong to the same project (projectID).
// Secrets that already exist by name in dstEnvID are skipped (not overwritten).
// Only the latest version of each secret is copied. clonedBy is the username
// credited in audit events; actorID is the user's numeric ID (used for the
// per-secret read permission check).
func (c *KeyorixCore) CloneEnvironment(ctx context.Context, projectID, srcEnvID, dstEnvID uint, clonedBy string, actorID uint) (*EnvCloneResult, error) {
	if projectID == 0 || srcEnvID == 0 || dstEnvID == 0 {
		return nil, validationErrorf("%s: %s", i18n.T("ErrorValidation", nil), "project, source and destination environment IDs are required")
	}
	if srcEnvID == dstEnvID {
		return nil, validationErrorf("%s: %s", i18n.T("ErrorValidation", nil), "source and destination environments must differ")
	}
	if err := c.requireActorActive(ctx, actorID); err != nil { // #4159
		return nil, err
	}

	// Verify both environments belong to the authorised project.
	srcEnv, err := c.storage.GetEnvironment(ctx, srcEnvID)
	if err != nil {
		return nil, cloneEnvironmentReadError("source environment", err)
	}
	dstEnv, err := c.storage.GetEnvironment(ctx, dstEnvID)
	if err != nil {
		return nil, cloneEnvironmentReadError("destination environment", err)
	}
	if srcEnv.ProjectID != projectID || dstEnv.ProjectID != projectID {
		return nil, validationErrorf("%s: %s", i18n.T("ErrorValidation", nil), "both environments must belong to the given project")
	}
	// #4161: the route gate — secrets.write on the project (creates in the
	// destination) and secrets.read on the source environment (reads values) — is
	// decided here as well. The per-secret read check inside CopySecret stays; this
	// is the role-based requirement the transports put in front of it.
	if err := c.requireScopedGates(ctx, actorID,
		scopedGate{permSecretsWrite, Scope{ProjectID: projectID}},
		scopedGate{permSecretsRead, Scope{ProjectID: projectID, EnvironmentID: srcEnvID}},
	); err != nil {
		return nil, err
	}

	// #4718: the clone is many transactions (one per copied secret, each committing
	// its own secret.created row with the copy, CopySecret), so no single transaction
	// can hold the change and a summary row. The operation's own record is written
	// FIRST, fail-closed: an audit log that refuses it clones nothing. The counts
	// summary after the loop describes copies that are each already on record.
	pid := projectID
	if !c.writeAuditEventFull(ctx, EventEnvironmentCloneStarted, actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("environment %d (%s) cloning into %d (%s) by %q", srcEnvID, srcEnv.Name, dstEnvID, dstEnv.Name, clonedBy)) {
		return nil, fmt.Errorf("%w: audit event %q was not recorded; nothing was cloned", ErrMutationAuditUnavailable, EventEnvironmentCloneStarted)
	}

	result := &EnvCloneResult{
		SourceEnv: srcEnv.Name,
		DestEnv:   dstEnv.Name,
	}

	// Page through the source environment's secrets.
	trueVal := true
	for page := 1; ; page++ {
		secrets, total, lerr := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			EnvironmentID: &srcEnvID,
			IsSecret:      &trueVal, // only real secrets, not folders
			Page:          page,
			PageSize:      cloneEnvPageSize,
		})
		if lerr != nil {
			return result, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), lerr)
		}

		c.cloneSecretPage(ctx, secrets, dstEnvID, clonedBy, actorID, result)

		if len(secrets) < cloneEnvPageSize || int64(page*cloneEnvPageSize) >= total {
			break
		}
	}

	// Written unconditionally, not just per-secret via CopySecret above: a clone
	// of an empty source environment (zero secrets to copy) would otherwise
	// leave this whole operation with no audit trail at all (F3, audit-
	// completeness campaign).
	c.writeAuditEventFull(ctx, "environment.cloned", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("environment %d (%s) cloned into %d (%s): %d secret(s) copied, %d skipped",
			srcEnvID, srcEnv.Name, dstEnvID, dstEnv.Name, result.SecretsCloned, result.SecretsSkipped))
	return result, nil
}

// cloneSecretPage copies one page of secrets into dstEnvID, recording skips on failure.
func (c *KeyorixCore) cloneSecretPage(ctx context.Context, secrets []*models.SecretNode, dstEnvID uint, clonedBy string, actorID uint, result *EnvCloneResult) {
	for _, s := range secrets {
		if _, cerr := c.CopySecret(ctx, s.ID, dstEnvID, "", clonedBy, actorID, "", ""); cerr != nil {
			result.SecretsSkipped++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", s.Name, cerr))
			continue
		}
		result.SecretsCloned++
	}
}
