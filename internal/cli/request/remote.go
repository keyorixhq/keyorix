// remote.go — server-backed (remote mode) helpers shared by the request
// subcommands' remote implementations.
//
// Every request subcommand is dual-mode (mirroring `keyorix secret`/`keyorix
// rbac`): when the CLI is configured to talk to a server (env vars or
// ~/.keyorix/cli.yaml written by `keyorix connect` / `keyorix auth login
// --server`), the command goes through the human-facing HTTP API so it
// operates on the SAME data the server and web UI show, instead of a stray
// local SQLite file. Without remote configuration it falls back to the
// embedded direct-DB path.
//
// Two access-request response fields have no JSON tag on
// internal/storage/models.AccessRequest/Project, so the server marshals them
// verbatim using their (capitalized) Go field names -- decoding directly into
// models.AccessRequest/models.Project here is deliberate, not an oversight
// (mirrors internal/cli/project/list.go's existing remote decode).
package request

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// resolveProjectIDByName finds a project's ID by name via GET /api/v1/projects.
// Exact match, mirroring common.LookupProjectIDByName's embedded-mode
// semantics (not rbac/remote.go's case-insensitive match) so a project name's
// resolution behaves identically whether this package is running against
// local storage or a remote server.
func resolveProjectIDByName(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var resp struct {
		Projects []*models.Project `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range resp.Projects {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found", name)
}

// fetchAccessRequests returns every access request for projectID via
// GET /api/v1/projects/{id}/access-requests -- the same project-scoped,
// roles.assign-gated endpoint the equivalent embedded ListAccessRequests call
// reads from, so this introduces no privilege requirement beyond what that
// route already demands.
func fetchAccessRequests(ctx context.Context, rc *common.RemoteClient, projectID uint) ([]*models.AccessRequest, error) {
	var resp struct {
		AccessRequests []*models.AccessRequest `json:"access_requests"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/projects/%d/access-requests", projectID), &resp); err != nil {
		return nil, err
	}
	return resp.AccessRequests, nil
}

// fetchAccessRequest finds one access request by ID within projectID's list.
// There is no human-facing GET-by-ID-alone route (only the /system
// RemoteStorage storage-primitive proxy has one, and that proxy is off-limits
// to the CLI -- see internal/cli/user/create.go's package doc for why), so
// this is deliberately scoped to a single project's list rather than scanning
// every project: scanning across projects the caller doesn't administer would
// 403 on roles.assign it has no reason to hold, which review/list's caller
// (already required to hold roles.assign on the ONE project they're
// reviewing) never needs to do.
func fetchAccessRequest(ctx context.Context, rc *common.RemoteClient, projectID, reqID uint) (*models.AccessRequest, error) {
	requests, err := fetchAccessRequests(ctx, rc, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up access request %d: %w", reqID, err)
	}
	for _, r := range requests {
		if r.ID == reqID {
			return r, nil
		}
	}
	return nil, fmt.Errorf("access request %d not found in project (id=%d)", reqID, projectID)
}

// resolveSecretIDRemote resolves a secret ID from either a numeric ID
// (returned unchanged) or a "project/environment/name" reference, mirroring
// core.ResolveSecretRef's own name-based resolution exactly (project name,
// then environment name within that project, then secret name within that
// environment) but over HTTP: GET /api/v1/projects (name lookup, shared with
// resolveProjectIDByName), GET /api/v1/projects/{id}/environments (name
// lookup), then GET /api/v1/secrets/by-name (metadata only). Deliberately
// NOT GET /api/v1/secrets/value?ref=... (secret/get.go's own --ref path):
// that route reads and audits the secret's VALUE, which the very reason this
// command exists is that the caller does NOT yet have permission to do.
func resolveSecretIDRemote(ctx context.Context, rc *common.RemoteClient, secretID uint, ref string) (uint, error) {
	if secretID != 0 {
		return secretID, nil
	}
	projectName, envName, secretName, err := core.ParseSecretRef(ref)
	if err != nil {
		return 0, fmt.Errorf("resolve ref %q: %w", ref, err)
	}
	projectID, err := resolveProjectIDByName(ctx, rc, projectName)
	if err != nil {
		return 0, fmt.Errorf("resolve ref %q: %w", ref, err)
	}
	var envResp struct {
		Environments []*models.Environment `json:"environments"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/projects/%d/environments", projectID), &envResp); err != nil {
		return 0, fmt.Errorf("resolve ref %q: failed to list environments: %w", ref, err)
	}
	var envID uint
	for _, e := range envResp.Environments {
		if e.Name == envName {
			envID = e.ID
			break
		}
	}
	if envID == 0 {
		return 0, fmt.Errorf("resolve ref %q: environment %q not found in project %q", ref, envName, projectName)
	}
	q := url.Values{}
	q.Set("name", secretName)
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	q.Set("environment_id", strconv.FormatUint(uint64(envID), 10))
	var secret models.SecretNode
	if err := rc.Get(ctx, "/api/v1/secrets/by-name?"+q.Encode(), &secret); err != nil {
		return 0, fmt.Errorf("resolve ref %q: %w", ref, err)
	}
	if secret.ID == 0 {
		return 0, fmt.Errorf("resolve ref %q: secret not found", ref)
	}
	return secret.ID, nil
}

// remoteUserLabel renders a user ID as "username (#id)" via GET
// /api/v1/users/{id}, falling back to "#id" on any error -- mirrors
// userLabel's (request.go) local fallback semantics exactly, including
// swallowing a permission error rather than failing the whole list/review
// operation: GET /api/v1/users/{id} needs users.read, a permission bundle
// distinct from the roles.assign this package's admin-driven commands
// already require, and a reviewer without it should still see request IDs,
// just without a friendly username label.
func remoteUserLabel(ctx context.Context, rc *common.RemoteClient, userID uint) string {
	var resp struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/users/%d", userID), &resp); err != nil || resp.ID == 0 {
		return fmt.Sprintf("#%d", userID)
	}
	return fmt.Sprintf("%s (#%d)", resp.Username, userID)
}
