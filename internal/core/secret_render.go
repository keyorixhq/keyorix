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
// output). Values are never logged — but each resolved value IS recorded as a secret read
// (audit event + access log), so a bulk render can't be used as a covert exfiltration
// channel invisible to the audit trail and the anomaly detector. username/ip/ua attribute
// the reads (pass-through from the request); empty is tolerated.
func (c *KeyorixCore) RenderSecretTemplate(ctx context.Context, template string, projectID, userID uint, username, ip, ua string) (string, error) {
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
			// TMPL-002: use the same sentinel as "secret not found" to avoid leaking
			// the environment name in the HTTP response via sendRenderTemplateError.
			return "", ErrSecretRefNotFound
		}
		secret, err := c.storage.GetSecretByName(ctx, secretName, projectID, envID)
		if err != nil || secret == nil {
			// A reference to a name that doesn't exist. Deliberately the SAME sentinel
			// (same error, same eventual HTTP status/message) as "exists but you can't
			// read it" below — see the permission check for why (#181).
			return "", ErrSecretRefNotFound
		}
		// Run the permission check BEFORE anything that could distinguish this from the
		// "doesn't exist" branch above. GetSecretByName has no ACL of its own, so if we
		// let a permission failure surface its own distinct error/status here, a
		// `viewer`-role project member with no access to this secret could enumerate
		// candidate names via ${secret:<env>/<guess>} and learn existence per guess from
		// 404-vs-403 alone — info never surfaced by their normal scoped listing. Folding
		// both outcomes into the identical ErrSecretRefNotFound closes that oracle (#181).
		if _, err := c.ValidateSecretAccess(ctx, secret.ID, userID); err != nil {
			return "", ErrSecretRefNotFound
		}
		val, err := c.getSecretValueForUser(ctx, secret.ID, userID)
		if err != nil {
			return "", err
		}
		// Record the read like the single-secret read path does, so a bulk render is
		// auditable and visible to the anomaly detector (detached so it survives the
		// request and never blocks the render).
		goSafe(func() {
			c.LogSecretReadWithProject(DetachedAuditContext(ctx), userID, secret.ID, projectID, username, secretName, ip, ua)
		}) // #nosec G118
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
