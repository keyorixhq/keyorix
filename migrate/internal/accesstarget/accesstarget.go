// Package accesstarget implements accessplan.KeyorixReader (and the Project/Environment
// listing PathMapper construction needs) over the generated apiclient — ADR-114's "talks to
// Keyorix only through the public REST API" rule, same as internal/target does for secret
// values. Every call here is read-only: `vault plan-access` never writes to Keyorix.
package accesstarget

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
)

// Client implements accessplan.KeyorixReader over the generated apiclient.
type Client struct {
	api *apiclient.ClientWithResponses
}

func New(api *apiclient.ClientWithResponses) *Client {
	return &Client{api: api}
}

// ListProjects returns every project, for PathMapper construction.
func (c *Client) ListProjects(ctx context.Context) ([]accessplan.ProjectRef, error) {
	resp, err := c.api.ListProjectsWithResponse(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Projects == nil {
		return nil, apiErr("list projects", resp.StatusCode(), resp.Body)
	}
	out := make([]accessplan.ProjectRef, 0, len(*resp.JSON200.Data.Projects))
	for _, p := range *resp.JSON200.Data.Projects {
		if p.Id == nil || p.Name == nil {
			continue
		}
		out = append(out, accessplan.ProjectRef{ID: *p.Id, Name: *p.Name})
	}
	return out, nil
}

// ListEnvironments returns every environment under projectID, for PathMapper construction.
func (c *Client) ListEnvironments(ctx context.Context, projectID int) ([]accessplan.EnvironmentRef, error) {
	resp, err := c.api.ListProjectEnvironmentsWithResponse(ctx, uint32(projectID), nil) //nolint:gosec // projectID always comes from ListProjects' own result, never user input directly cast past int range.
	if err != nil {
		return nil, fmt.Errorf("list environments for project %d: %w", projectID, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Environments == nil {
		return nil, apiErr("list environments", resp.StatusCode(), resp.Body)
	}
	out := make([]accessplan.EnvironmentRef, 0, len(*resp.JSON200.Data.Environments))
	for _, e := range *resp.JSON200.Data.Environments {
		if e.Id == nil || e.Name == nil {
			continue
		}
		out = append(out, accessplan.EnvironmentRef{ID: *e.Id, Name: *e.Name})
	}
	return out, nil
}

// RoleDescriptionByName implements accessplan.KeyorixReader.
func (c *Client) RoleDescriptionByName(ctx context.Context, name string) (string, bool, error) {
	resp, err := c.api.GetRoleByNameWithResponse(ctx, &apiclient.GetRoleByNameParams{Name: name})
	if err != nil {
		return "", false, fmt.Errorf("look up role %q: %w", name, err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return "", false, nil
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return "", false, apiErr("look up role", resp.StatusCode(), resp.Body)
	}
	desc := ""
	if resp.JSON200.Data.Description != nil {
		desc = *resp.JSON200.Data.Description
	}
	return desc, true, nil
}

// findMachineIdentity lists every machine identity in projectID and returns the one named name,
// or found=false. There is no by-name lookup route (unlike roles' GET /roles/by-name), so this
// lists and searches client-side — acceptable for a one-shot CLI command against a bounded
// per-project machine identity count, not a hot path.
func (c *Client) findMachineIdentity(ctx context.Context, projectID int, name string) (*apiclient.MachineIdentity, bool, error) {
	resp, err := c.api.ListMachineIdentitiesWithResponse(ctx, projectID)
	if err != nil {
		return nil, false, fmt.Errorf("list machine identities in project %d: %w", projectID, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.MachineIdentities == nil {
		return nil, false, apiErr("list machine identities", resp.StatusCode(), resp.Body)
	}
	for i, m := range *resp.JSON200.Data.MachineIdentities {
		if m.Name != nil && *m.Name == name {
			return &(*resp.JSON200.Data.MachineIdentities)[i], true, nil
		}
	}
	return nil, false, nil
}

// MachineIdentityDescriptionByName implements accessplan.KeyorixReader.
func (c *Client) MachineIdentityDescriptionByName(ctx context.Context, projectID int, name string) (string, bool, error) {
	m, found, err := c.findMachineIdentity(ctx, projectID, name)
	if err != nil || !found {
		return "", found, err
	}
	desc := ""
	if m.Description != nil {
		desc = *m.Description
	}
	return desc, true, nil
}

// MachineHasRoleGrant implements accessplan.KeyorixReader.
func (c *Client) MachineHasRoleGrant(ctx context.Context, projectID int, machineName, roleName string) (bool, error) {
	m, found, err := c.findMachineIdentity(ctx, projectID, machineName)
	if err != nil {
		return false, err
	}
	if !found || m.Id == nil {
		return false, nil // the identity doesn't exist yet — apply-access creates it first.
	}
	resp, err := c.api.ListMachineRolesWithResponse(ctx, projectID, *m.Id)
	if err != nil {
		return false, fmt.Errorf("list roles for machine identity %q: %w", machineName, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Roles == nil {
		return false, apiErr("list machine roles", resp.StatusCode(), resp.Body)
	}
	for _, r := range *resp.JSON200.Data.Roles {
		if r.Name != nil && *r.Name == roleName {
			return true, nil
		}
	}
	return false, nil
}

// MachineHasOIDCBinding implements accessplan.KeyorixReader.
func (c *Client) MachineHasOIDCBinding(ctx context.Context, projectID int, machineName, issuer, subject string) (bool, error) {
	m, found, err := c.findMachineIdentity(ctx, projectID, machineName)
	if err != nil {
		return false, err
	}
	if !found || m.Id == nil {
		return false, nil
	}
	resp, err := c.api.ListOIDCBindingsWithResponse(ctx, projectID, *m.Id)
	if err != nil {
		return false, fmt.Errorf("list OIDC bindings for machine identity %q: %w", machineName, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Bindings == nil {
		return false, apiErr("list oidc bindings", resp.StatusCode(), resp.Body)
	}
	for _, b := range *resp.JSON200.Data.Bindings {
		if b.Issuer != nil && b.Subject != nil && *b.Issuer == issuer && *b.Subject == subject {
			return true, nil
		}
	}
	return false, nil
}

type apiErrorBody struct {
	Message string `json:"message"`
}

// apiErr mirrors internal/target's own helper: never interpolates a response body verbatim,
// only the structured "message" field, so an unexpected response shape can't echo request/
// response content into an error string this tool's report then surfaces.
func apiErr(action string, statusCode int, body []byte) error {
	var eb apiErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Message != "" {
		return fmt.Errorf("%s failed: %s (HTTP %d)", action, eb.Message, statusCode)
	}
	return fmt.Errorf("%s failed: HTTP %d", action, statusCode)
}
