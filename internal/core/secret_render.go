// secret_render.go — server-side rendering of templates that embed secret
// references (${secret:<environment>/<name>}). Resolution is scoped to one project,
// where an environment name and a secret name are unique, so a reference resolves
// unambiguously. Each referenced value is read through the per-secret permission
// check, so the caller only ever renders secrets they may read.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/secrettemplate"
)

// RenderSecretTemplate expands ${secret:<environment>/<name>} references in template
// against the given project, returning the rendered output. A reference to an unknown
// environment/secret, or one the user cannot read, fails the whole render (no partial
// output). Values are never logged.
func (c *KeyorixCore) RenderSecretTemplate(ctx context.Context, template string, projectID, userID uint) (string, error) {
	if projectID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if userID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	envs, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("list environments: %w", err)
	}
	envByName := make(map[string]uint, len(envs))
	for _, e := range envs {
		envByName[e.Name] = e.ID
	}

	return secrettemplate.Render(template, func(ref string) (string, error) {
		envName, secretName, err := splitRenderRef(ref)
		if err != nil {
			return "", err
		}
		envID, ok := envByName[envName]
		if !ok {
			return "", fmt.Errorf("environment %q not found in this project", envName)
		}
		secret, err := c.storage.GetSecretByName(ctx, secretName, projectID, envID)
		if err != nil || secret == nil {
			return "", fmt.Errorf("secret %q not found in %s", secretName, envName)
		}
		val, err := c.GetSecretValueWithPermissionCheck(ctx, secret.ID, userID)
		if err != nil {
			return "", err
		}
		return string(val), nil
	})
}

// splitRenderRef splits "<environment>/<name>"; the name may contain further slashes.
func splitRenderRef(ref string) (env, name string, err error) {
	ref = strings.TrimSpace(ref)
	i := strings.IndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("invalid reference %q: expected \"<environment>/<name>\"", ref)
	}
	return ref[:i], ref[i+1:], nil
}
