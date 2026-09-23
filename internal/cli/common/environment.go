// environment.go — Helpers for resolving an environment name to its ID within
// a specific project, over the remote API.
package common

import (
	"context"
	"fmt"
	"strings"
)

// ResolveEnvironmentIDRemote resolves an environment name to its uint ID
// within projectID, via GET /api/v1/projects/{id}/environments — the
// project-scoped listing route, not the unscoped /api/v1/secrets `environment`
// query parameter (which the server does not filter by; see
// server/http/handlers/secrets_list.go). Environment names are unique per
// project, not globally, so this must always be resolved within a project,
// never on its own.
func ResolveEnvironmentIDRemote(ctx context.Context, rc *RemoteClient, projectID uint, name string) (uint, error) {
	var resp struct {
		Environments []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/environments", projectID)
	if err := rc.Get(ctx, path, &resp); err != nil {
		return 0, fmt.Errorf("failed to list environments: %w", err)
	}
	for _, e := range resp.Environments {
		if strings.EqualFold(e.Name, name) {
			return e.ID, nil
		}
	}
	return 0, fmt.Errorf("environment %q not found in this project", name)
}
