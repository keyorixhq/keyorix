package core

import (
	"context"
	"errors"
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Sentinel errors for reference resolution, so callers can map them to the right HTTP
// status: a malformed reference is a 400, a reference that resolves to nothing is a 404.
var (
	// ErrSecretRefInvalid means the reference string was not "project/environment/name".
	ErrSecretRefInvalid = errors.New("invalid secret reference")
	// ErrSecretRefNotFound means no project/environment/secret matched the reference.
	ErrSecretRefNotFound = errors.New("secret reference not found")
)

// ParseSecretRef splits a "project/environment/name" reference into its three parts.
// The secret name may itself contain slashes (a path-like name); only the first two
// segments are the project and environment. All three parts must be non-empty.
//
// A three-level reference is used (rather than the agent's "environment/name") because
// only project names are globally unique — an environment named "prod" can exist in
// several projects, so "prod/db" would be ambiguous. "project/prod/db" is unambiguous.
func ParseSecretRef(ref string) (project, environment, name string, err error) {
	parts := strings.SplitN(strings.TrimSpace(ref), "/", 3)
	if len(parts) != 3 {
		return "", "", "", ErrSecretRefInvalid
	}
	project, environment, name = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	if project == "" || environment == "" || name == "" {
		return "", "", "", ErrSecretRefInvalid
	}
	return project, environment, name, nil
}

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
