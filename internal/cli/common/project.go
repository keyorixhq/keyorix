// project.go — Helpers for resolving the active project context in CLI commands.
//
// ADR-016: Resolution priority: --project flag → KEYORIX_PROJECT env → cli.yaml active_project → error
package common

import (
	"context"
	"fmt"
	"os"
	"strings"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ResolveProject returns the active project name from the resolution chain.
// Priority: explicit flag value → KEYORIX_PROJECT env var → cli.yaml active_project.
// Returns an error if none of these are set and the caller requires a project.
func ResolveProject(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("KEYORIX_PROJECT"); v != "" {
		return v, nil
	}
	cfg, err := cliconfig.LoadCLIConfig("")
	if err == nil && cfg.ActiveProject != "" {
		return cfg.ActiveProject, nil
	}
	return "", fmt.Errorf(
		"no project specified — use --project, set KEYORIX_PROJECT, or run 'keyorix project use <name>'",
	)
}

// LookupProjectIDByName resolves a project name to its uint ID using storage directly.
func LookupProjectIDByName(ctx context.Context, st storage.Storage, name string) (uint, error) {
	projects, err := st.ListProjects(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range projects {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found", name)
}

// ResolveProjectIDRemote resolves a project name to its uint ID against a
// remote server via GET /api/v1/projects, matched case-insensitively (same
// convention as the CLI's other project-name lookups). Shared by every
// remote-mode command that must scope a request to one project rather than
// listing across every project the caller can read.
func ResolveProjectIDRemote(ctx context.Context, rc *RemoteClient, name string) (uint, error) {
	var resp struct {
		Projects []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range resp.Projects {
		if strings.EqualFold(p.Name, name) {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found — run 'keyorix project list' to see available projects", name)
}
