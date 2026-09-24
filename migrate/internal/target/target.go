// Package target defines the narrow surface keyorix-migrate needs against a Keyorix server,
// and a real implementation over the generated apiclient. Kept as an interface (API) so
// internal/plan can be unit-tested against a fake without a live server — the CI integration
// test (docs/design-keyorix-migrate.md's "Testing" section) then exercises the real
// implementation end-to-end.
package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
)

// API is every operation keyorix-migrate needs against a Keyorix server, scoped to one
// project/environment (set when the implementation is constructed).
type API interface {
	// LookupByName returns the secret ID for name, or found=false if none exists.
	LookupByName(ctx context.Context, name string) (id int, found bool, err error)
	// Metadata returns the metadata map stored on secret id (never the value).
	Metadata(ctx context.Context, id int) (map[string]string, error)
	// Value returns the decrypted value of secret id. Callers must never log or print it
	// outside a value comparison — see docs/design-keyorix-migrate.md's "Never log, print,
	// or report a secret value".
	Value(ctx context.Context, id int) (string, error)
	// Create creates a new secret and returns its ID.
	Create(ctx context.Context, name, value string, metadata map[string]string) (id int, err error)
	// UpdateValue overwrites the value of an existing secret.
	UpdateValue(ctx context.Context, id int, value string) error
}

// Client implements API over the generated apiclient, scoped to one project/environment.
type Client struct {
	api           *apiclient.ClientWithResponses
	projectID     int
	environmentID int
}

// New builds a Client bound to one project/environment — every keyorix-migrate run targets
// exactly one (docs/design-keyorix-migrate.md: "--project"/"--environment" required flags).
func New(api *apiclient.ClientWithResponses, projectID, environmentID int) *Client {
	return &Client{api: api, projectID: projectID, environmentID: environmentID}
}

func (c *Client) LookupByName(ctx context.Context, name string) (int, bool, error) {
	resp, err := c.api.GetSecretByNameWithResponse(ctx, &apiclient.GetSecretByNameParams{
		Name:          name,
		ProjectId:     c.projectID,
		EnvironmentId: c.environmentID,
	})
	if err != nil {
		return 0, false, fmt.Errorf("look up secret %q: %w", name, err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return 0, false, nil
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.ID == nil {
		return 0, false, apiErr("look up secret", resp.StatusCode(), resp.Body)
	}
	return *resp.JSON200.Data.ID, true, nil
}

// secretNodeMetadata decodes just the "Metadata" field off a raw secret-node JSON body — the
// generated Secret/SecretGetResult response types don't expose it (a documented schema gap,
// see docs/design-keyorix-migrate.md's "Generated API client" section), but the real handler
// serializes the full models.SecretNode, which does carry it on the wire.
type secretNodeMetadata struct {
	Metadata map[string]string `json:"Metadata"`
}

func (c *Client) Metadata(ctx context.Context, id int) (map[string]string, error) {
	resp, err := c.api.GetSecretWithResponse(ctx, id, &apiclient.GetSecretParams{})
	if err != nil {
		return nil, fmt.Errorf("get secret %d metadata: %w", id, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, apiErr("get secret metadata", resp.StatusCode(), resp.Body)
	}
	var env struct {
		Data secretNodeMetadata `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return nil, fmt.Errorf("decode secret %d metadata: %w", id, err)
	}
	return env.Data.Metadata, nil
}

func (c *Client) Value(ctx context.Context, id int) (string, error) {
	includeValue := true
	resp, err := c.api.GetSecretWithResponse(ctx, id, &apiclient.GetSecretParams{IncludeValue: &includeValue})
	if err != nil {
		return "", fmt.Errorf("get secret %d value: %w", id, err)
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Value == nil {
		return "", apiErr("get secret value", resp.StatusCode(), resp.Body)
	}
	return *resp.JSON200.Data.Value, nil
}

func (c *Client) Create(ctx context.Context, name, value string, metadata map[string]string) (int, error) {
	body := apiclient.CreateSecretJSONRequestBody{
		Name:          name,
		Value:         value,
		Type:          "generic",
		ProjectId:     &c.projectID,
		EnvironmentId: c.environmentID,
	}
	if len(metadata) > 0 {
		body.Metadata = &metadata
	}
	resp, err := c.api.CreateSecretWithResponse(ctx, body)
	if err != nil {
		return 0, fmt.Errorf("create secret %q: %w", name, err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.ID == nil {
		return 0, apiErr("create secret", resp.StatusCode(), resp.Body)
	}
	return *resp.JSON201.Data.ID, nil
}

func (c *Client) UpdateValue(ctx context.Context, id int, value string) error {
	resp, err := c.api.UpdateSecretWithResponse(ctx, id, apiclient.UpdateSecretJSONRequestBody{Value: &value})
	if err != nil {
		return fmt.Errorf("update secret %d: %w", id, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return apiErr("update secret", resp.StatusCode(), resp.Body)
	}
	return nil
}

type apiErrorBody struct {
	Message string `json:"message"`
}

// apiErr builds a readable error from a non-2xx response body. Deliberately does not
// interpolate resp.Body verbatim into the error — only the structured "message" field, so an
// unexpected response shape (which could, in principle, echo request content back) never
// reaches an error string that this tool's report then surfaces (docs/design-keyorix-migrate.md's
// "Never log, print, or report a secret value").
func apiErr(action string, statusCode int, body []byte) error {
	var eb apiErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Message != "" {
		return fmt.Errorf("%s failed: %s (HTTP %d)", action, eb.Message, statusCode)
	}
	return fmt.Errorf("%s failed: HTTP %d", action, statusCode)
}
