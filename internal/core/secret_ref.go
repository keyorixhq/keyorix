package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ResolveSecretRef resolves a "project/environment/name" reference to its secret. It
// performs no value read and no read-count side effects — it only locates the secret so
// callers can authorize against (and then read) it by id. Returns ErrSecretRefInvalid
// for a malformed reference and ErrSecretRefNotFound when nothing matches.
func (c *KeyorixCore) ResolveSecretRef(ctx context.Context, ref string) (*models.SecretNode, error) {
	projectName, envName, secretName, err := ParseSecretRef(ref)
	if err != nil {
		return nil, err
	}

	projects, err := c.storage.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	var projectID uint
	for _, p := range projects {
		if p.Name == projectName {
			projectID = p.ID
			break
		}
	}
	if projectID == 0 {
		return nil, ErrSecretRefNotFound
	}

	envs, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	var envID uint
	for _, e := range envs {
		if e.Name == envName {
			envID = e.ID
			break
		}
	}
	if envID == 0 {
		return nil, ErrSecretRefNotFound
	}

	secret, err := c.storage.GetSecretByName(ctx, secretName, projectID, envID)
	if err != nil || secret == nil {
		return nil, ErrSecretRefNotFound
	}
	return secret, nil
}
