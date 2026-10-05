package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// resolveProjectRef resolves a --project / KEYORIX_PROJECT / active-project value
// (a project NAME, or its numeric ID) to the project's name and numeric ID. Every
// project-scoped command's own resolver delegates here (#2562).
//
// Resolution order:
//
//  1. GET /api/v1/projects (the project listing). Since #2780 it serves every
//     caller the projects they can read -- an admin-tier caller gets all of them, a
//     project-scoped caller gets theirs -- so this path now resolves a NAME for a
//     least-privilege caller too, which is the common case it used to fail. On 200:
//     match ref by name (case-insensitively when fold is set, matching what each
//     caller did before), then -- only if no name matched -- by numeric ID. A
//     caller with no project grant gets 200 with an empty list, and falls through
//     to the "not found" error below rather than to step 2.
//
//  2. On a 403 from that listing, a NUMERIC ref is resolved through
//     GET /api/v1/projects/{id}, the per-project read the server authorizes against
//     the caller's grant on exactly that project
//     (RequireScopedPermission(secrets.read, projectScope)). The server still
//     decides: a project the caller holds no grant in answers 403 there too, and
//     this function surfaces that as an error, never as a resolved ID.
//
//     This arm is now a safety net rather than the ordinary least-privilege path:
//     `?include_deleted=true` still 403s a non-global caller, and an older server
//     predating #2780 still 403s the plain listing. It is deliberately kept so the
//     CLI keeps working against both.
//
//  3. A non-numeric ref after a 403 cannot be resolved without a listing the
//     caller is allowed to see, so the error says exactly that and names the
//     numeric-ID form as the way through.
//
// This deliberately loosens nothing server-side: it only stops the CLI from
// making a listing a hard prerequisite of commands whose real endpoint is
// project-scoped.
func resolveProjectRef(ctx context.Context, client *apiclient.ClientWithResponses, ref string, fold bool) (name string, id int, err error) {
	p, err := resolveProject(ctx, client, ref, fold)
	if err != nil {
		return "", 0, err
	}
	return p.Name, int(p.ID), nil
}

// resolveProject is resolveProjectRef returning the whole projectListItem
// (project.go's subcommands also print the description).
func resolveProject(ctx context.Context, client *apiclient.ClientWithResponses, ref string, fold bool) (projectListItem, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return projectListItem{}, fmt.Errorf("no project given: pass --project or set KEYORIX_PROJECT")
	}
	resp, err := client.ListProjectsWithResponse(ctx, nil)
	if err != nil {
		return projectListItem{}, fmt.Errorf("failed to list projects: %w", err)
	}
	switch {
	case resp.StatusCode() == http.StatusForbidden:
		return resolveProjectScoped(ctx, client, ref)
	case resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Projects == nil:
		return projectListItem{}, fmt.Errorf("failed to list projects: HTTP %d", resp.StatusCode())
	}
	projects := *resp.JSON200.Data.Projects
	for _, p := range projects {
		if p.Name == nil {
			continue
		}
		if *p.Name == ref || (fold && strings.EqualFold(*p.Name, ref)) {
			return summaryToItem(p.Id, p.Name, p.Description), nil
		}
	}
	if n, ok := parseProjectID(ref); ok {
		for _, p := range projects {
			if derefInt(p.Id) == n {
				return summaryToItem(p.Id, p.Name, p.Description), nil
			}
		}
	}
	return projectListItem{}, fmt.Errorf("project %q not found — run 'keyorix project list' to see available projects", ref)
}

// resolveProjectScoped is resolveProject's path for a caller the global
// listing refused (HTTP 403): only a numeric ref can be resolved, and only
// through the per-project read the server authorizes on that one project.
func resolveProjectScoped(ctx context.Context, client *apiclient.ClientWithResponses, ref string) (projectListItem, error) {
	n, ok := parseProjectID(ref)
	if !ok {
		return projectListItem{}, fmt.Errorf("cannot resolve project name %q: listing all projects requires a deployment-wide role "+
			"(GET /api/v1/projects returned HTTP 403). If you hold a grant on this project, pass its numeric ID "+
			"instead (for example --project 2, or KEYORIX_PROJECT=2)", ref)
	}
	resp, err := client.GetProjectWithResponse(ctx, uint32(n)) // #nosec G115 -- parseProjectID bounds n to (0, MaxUint32]
	if err != nil {
		return projectListItem{}, fmt.Errorf("failed to get project %d: %w", n, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		if resp.StatusCode() == http.StatusForbidden || resp.StatusCode() == http.StatusNotFound {
			return projectListItem{}, fmt.Errorf("project %d not found or you hold no grant on it (HTTP %d)", n, resp.StatusCode())
		}
		return projectListItem{}, fmt.Errorf("failed to get project %d: HTTP %d", n, resp.StatusCode())
	}
	d := resp.JSON200.Data
	return projectListItem{ID: uint(n), Name: derefStr(d.Name), Description: derefStr(d.Description)}, nil // #nosec G115 -- n is positive
}

// parseProjectID reports whether ref is a positive project ID that fits the
// API's uint32 path parameter.
func parseProjectID(ref string) (int, bool) {
	n, err := strconv.ParseUint(ref, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return int(n), true
}

// resolveProjectItem is resolveProject for project.go's subcommands, which
// match names case-insensitively.
func resolveProjectItem(ctx context.Context, client *apiclient.ClientWithResponses, ref string) (projectListItem, error) {
	return resolveProject(ctx, client, ref, true)
}

func summaryToItem(id *int, name, description *string) projectListItem {
	return projectListItem{ID: uint(derefInt(id)), Name: derefStr(name), Description: derefStr(description)} // #nosec G115 -- server-issued positive ID
}
