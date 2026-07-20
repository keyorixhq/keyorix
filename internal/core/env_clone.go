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
)

const cloneEnvPageSize = 500

// EnvCloneResult summarises the outcome of a CloneEnvironment call.
type EnvCloneResult struct {
	SourceEnv      string
	DestEnv        string
	SecretsCloned  int
	SecretsSkipped int   // secrets that already exist in dest (skipped, not overwritten)
	Errors         []string
}

// CloneEnvironment copies all active secrets from srcEnvID to dstEnvID.
// Both environments must belong to the same project (projectID).
// Secrets that already exist by name in dstEnvID are skipped (not overwritten).
// Only the latest version of each secret is copied. clonedBy is the username
// credited in audit events; actorID is the user's numeric ID (used for the
// per-secret read permission check).
func (c *KeyorixCore) CloneEnvironment(ctx context.Context, projectID, srcEnvID, dstEnvID uint, clonedBy string, actorID uint) (*EnvCloneResult, error) {
	if projectID == 0 || srcEnvID == 0 || dstEnvID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project, source and destination environment IDs are required")
	}
	if srcEnvID == dstEnvID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "source and destination environments must differ")
	}

	// Verify both environments belong to the authorised project.
	srcEnv, err := c.storage.GetEnvironment(ctx, srcEnvID)
	if err != nil {
		return nil, fmt.Errorf("%s: source environment: %w", i18n.T("ErrorValidation", nil), err)
	}
	dstEnv, err := c.storage.GetEnvironment(ctx, dstEnvID)
	if err != nil {
		return nil, fmt.Errorf("%s: destination environment: %w", i18n.T("ErrorValidation", nil), err)
	}
	if srcEnv.ProjectID != projectID || dstEnv.ProjectID != projectID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "both environments must belong to the given project")
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

		for _, s := range secrets {
			// CopySecret handles name-clash detection internally (CreateSecret fails if
			// the name already exists in dstEnvID) and records read + create audit events.
			if _, cerr := c.CopySecret(ctx, s.ID, dstEnvID, "", clonedBy, actorID, "", ""); cerr != nil {
				result.SecretsSkipped++
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", s.Name, cerr))
				continue
			}
			result.SecretsCloned++
		}

		if len(secrets) < cloneEnvPageSize || int64(page*cloneEnvPageSize) >= total {
			break
		}
	}

	return result, nil
}
