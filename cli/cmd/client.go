package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
	"github.com/keyorixhq/keyorix/cli/internal/credstore"
	"github.com/keyorixhq/keyorix/cli/internal/skew"
)

// resolveCredStore returns the one credential store this CLI uses (ADR-108 PR 0 decision --
// see internal/credstore's package doc comment).
func resolveCredStore() (*credstore.FileStore, error) {
	path, err := credstore.DefaultPath()
	if err != nil {
		return nil, err
	}
	return credstore.NewFileStore(path), nil
}

// resolveServerAndToken applies the precedence flag > env var > stored credentials file. A
// server URL is required; a token is optional (e.g. `login` itself has none yet).
func resolveServerAndToken(store *credstore.FileStore) (serverURL, token string, err error) {
	serverURL = os.Getenv("KEYORIX_SERVER")
	token = os.Getenv("KEYORIX_TOKEN")

	if serverURL != "" && token != "" {
		return serverURL, token, nil
	}

	creds, loadErr := store.Load()
	if serverURL == "" {
		serverURL = creds.ServerURL
	}
	if token == "" {
		token = creds.Token
	}
	if serverURL == "" {
		if loadErr != nil {
			return "", "", fmt.Errorf("no server configured: run \"keyorix-next login\" first, or set KEYORIX_SERVER (%w)", loadErr)
		}
		return "", "", fmt.Errorf("no server configured: run \"keyorix-next login\" first, or set KEYORIX_SERVER")
	}
	return serverURL, token, nil
}

// newAPIClient builds a generated client against serverURL, attaching an Authorization
// header when token is non-empty.
func newAPIClient(serverURL, token string) (*apiclient.ClientWithResponses, error) {
	var opts []apiclient.ClientOption
	if token != "" {
		opts = append(opts, apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		}))
	}
	return apiclient.NewClientWithResponses(serverURL, opts...)
}

// checkVersionSkew calls GET /api/v1/version and classifies the result via internal/skew.
// A 404 means the server predates this endpoint entirely (an "old server," not merely an
// old api_version) -- distinguished here rather than inside internal/skew, which only ever
// sees a successfully-parsed response.
func checkVersionSkew(ctx context.Context, client *apiclient.ClientWithResponses) (skew.Result, error) {
	resp, err := client.GetVersionWithResponse(ctx)
	if err != nil {
		return skew.Result{}, fmt.Errorf("contact server: %w", err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return skew.Result{
			Warning: "server predates the version-skew endpoint (GET /api/v1/version) -- it is likely a much older release; some commands may not be supported",
		}, nil
	}
	if resp.JSON200 == nil {
		return skew.Result{}, fmt.Errorf("unexpected response from GET /api/v1/version: HTTP %d", resp.StatusCode())
	}

	apiVersion := 0
	if resp.JSON200.ApiVersion != nil {
		apiVersion = *resp.JSON200.ApiVersion
	}
	minCLI := ""
	if resp.JSON200.MinimumCliVersion != nil {
		minCLI = *resp.JSON200.MinimumCliVersion
	}
	return skew.Check(cliversion.Version, cliversion.TargetAPIVersion, apiVersion, minCLI), nil
}
