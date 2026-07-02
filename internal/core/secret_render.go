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
// output). Values are never logged — but each DISTINCT resolved reference IS recorded as
// a secret read (audit event + access log), so a bulk render can't be used as a covert
// exfiltration channel invisible to the audit trail and the anomaly detector.
// username/ip/ua attribute the reads (pass-through from the request); empty is
// tolerated. Resolution is memoized per distinct reference within one render: the
// underlying secrettemplate.Render engine calls the resolver once per OCCURRENCE, so
// without memoizing here, the same reference repeated N times in one template would
// both charge TryIncrementSecretReadCount N times (able to exhaust a shared
// max_reads-limited secret's entire quota in a single request) and emit N audit/
// access-log rows for what is really one read.
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

	resolved := make(map[string]string)
	return secrettemplate.Render(template, func(ref string) (string, error) {
		if val, ok := resolved[ref]; ok {
			return val, nil
		}
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
		// Record the read like the single-secret read path does, so a bulk render is
		// auditable and visible to the anomaly detector (detached so it survives the
		// request and never blocks the render). Only reached once per distinct
		// reference (see the memoization check above).
		go c.LogSecretReadWithProject(DetachedAuditContext(ctx), userID, secret.ID, projectID, username, secretName, ip, ua) // #nosec G118
		resolved[ref] = string(val)
		return resolved[ref], nil
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
