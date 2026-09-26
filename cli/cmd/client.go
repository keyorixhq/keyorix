package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
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
// header when token is non-empty. Always uses apiclient.NewHardenedHTTPClient (request
// timeout, response-size cap, redirect refusal) instead of the generated client's bare
// &http.Client{} default -- see hardened_client.go's doc comment for why.
func newAPIClient(serverURL, token string) (*apiclient.ClientWithResponses, error) {
	opts := []apiclient.ClientOption{apiclient.WithHTTPClient(apiclient.NewHardenedHTTPClient())}
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

// apiClientWithSkewCheck resolves credentials, builds a client, and checks version skew
// against the server (docs/cli-split-inventory.md §7, PR 6's "skew check on every request"
// method, carried forward into PR 7/8/10) before returning -- unlike PR 1/2's per-command
// clients, which only checked skew from `login`/`status`. A Refuse result blocks the
// command outright; a Warning is printed to stderr (so it never pollutes stdout output a
// script might parse) and the command proceeds.
func apiClientWithSkewCheck(ctx context.Context) (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	client, err := newAPIClient(serverURL, token)
	if err != nil {
		return nil, err
	}
	skewResult, err := checkVersionSkew(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("version-skew check: %w", err)
	}
	if skewResult.Refuse {
		return nil, fmt.Errorf("incompatible with this server: %s", skewResult.Reason)
	}
	if skewResult.Warning != "" {
		fmt.Fprintln(os.Stderr, "Warning:", skewResult.Warning)
	}
	return client, nil
}

// apiEnvelope decodes the `{"success", "data", "message"}` envelope every handler
// (sendSuccess, server/http/handlers/helpers.go) wraps a 2xx response body in. T is the
// shape of the "data" field.
type apiEnvelope[T any] struct {
	Data T `json:"data"`
}

// decodeData unmarshals a 2xx response body's "data" field into T. Used for the routes
// this package calls whose generated response type has no typed JSON2xx field (no response
// schema was added to openapi.yaml for them -- see server/http/handlers/openapi.yaml's PR
// 6/7/8/10 additions and their doc comments for why a full typed schema wasn't worth it for
// a one-PR-only caller): the generated client always exposes the raw Body, decoding it here
// is the documented fallback (docs/cli-split-inventory.md §7).
func decodeData[T any](body []byte) (T, error) {
	var env apiEnvelope[T]
	if err := json.Unmarshal(body, &env); err != nil {
		var zero T
		return zero, fmt.Errorf("decode response: %w", err)
	}
	return env.Data, nil
}

// apiErrorBody mirrors the `{"error", "message"}` fields sendError
// (server/http/handlers/helpers.go) writes on a non-2xx response -- enough to surface a
// readable reason instead of a bare status code. Task requirement (PR 6 method, carried
// forward into PR 7/8/10, docs/cli-split-inventory.md §7): "surface ... refusals readably."
type apiErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// apiError builds a readable error for a non-2xx response: action describes what was being
// attempted (e.g. "update user"), statusCode and body come straight from the generated
// response. Falls back to a bare status code if body isn't the expected error shape (e.g.
// an empty body, or a transport-layer failure that never reached a handler).
//
// eb.Message is server-controlled text -- the server may be compromised, misconfigured, or
// (absent a validated TLS chain) MITM'd -- and this error's .Error() text reaches the
// operator's terminal raw via main.go's fmt.Fprintln(os.Stderr, "Error:", err). Route it
// through cliout.SanitizeForTerminal, the same defense every other piece of free text
// printed by this CLI goes through, so a crafted message can't inject a terminal escape
// sequence (found by FuzzApiError, CLI-FUZZ target 2).
func apiError(action string, statusCode int, body []byte) error {
	var eb apiErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Message != "" {
		return fmt.Errorf("%s failed: %s (HTTP %d)", action, cliout.SanitizeForTerminal(eb.Message), statusCode)
	}
	return fmt.Errorf("%s failed: HTTP %d", action, statusCode)
}
