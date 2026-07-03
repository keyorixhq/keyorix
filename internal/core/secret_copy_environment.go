// secret_copy_environment.go — bulk environment promotion: copy every secret in one
// environment into another of the same project (e.g. seed production from staging).
// Each secret goes through the single-secret CopySecret, so the same per-secret read
// authorization, value handling, and same-project guard apply; a name that already
// exists in the target is skipped (not overwritten), so a copy never clobbers. Reading
// values is permission-checked; creating in the target is authorized by the caller.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

const copyEnvPageSize = 500

// CopyEnvironmentSecrets copies every secret in sourceEnvID into targetEnvID (same
// project), returning how many were copied and how many were skipped (a name already
// present in the target, or a per-secret failure). The two environments must belong to
// the same project. Each per-secret copy is audited by CopySecret (a read on the
// source, a create on the destination); ip/ua attribute those events (pass-through
// from the request).
func (c *KeyorixCore) CopyEnvironmentSecrets(ctx context.Context, projectID, sourceEnvID, targetEnvID uint, actorUsername string, actorID uint, ip, ua string) (copied, skipped int, err error) {
	if projectID == 0 || sourceEnvID == 0 || targetEnvID == 0 {
		return 0, 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project, source and target environment IDs are required")
	}
	if sourceEnvID == targetEnvID {
		return 0, 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "source and target environments must differ")
	}

	// Both environments must belong to the authorized project — so the project-scoped
	// write gate the caller passed actually covers this copy (no cross-project bypass).
	srcEnv, err := c.storage.GetEnvironment(ctx, sourceEnvID)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	tgtEnv, err := c.storage.GetEnvironment(ctx, targetEnvID)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if srcEnv.ProjectID != projectID || tgtEnv.ProjectID != projectID {
		return 0, 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "both environments must belong to the given project")
	}

	// Page through the source environment's secrets.
	for page := 1; ; page++ {
		secrets, total, lerr := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			EnvironmentID: &sourceEnvID, Page: page, PageSize: copyEnvPageSize,
		})
		if lerr != nil {
			return copied, skipped, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), lerr)
		}
		for _, s := range secrets {
			if _, cerr := c.CopySecret(ctx, s.ID, targetEnvID, "", actorUsername, actorID, ip, ua); cerr != nil {
				// A name that already exists in the target is the common case — skip it
				// (never clobber); other per-secret failures are skipped too, best-effort.
				skipped++
				continue
			}
			copied++
		}
		if len(secrets) < copyEnvPageSize || int64(page*copyEnvPageSize) >= total {
			break
		}
	}
	return copied, skipped, nil
}
