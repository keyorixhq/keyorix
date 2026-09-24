package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
)

// resolveServerAndToken applies the precedence flag > env var, matching cli/cmd/client.go's
// resolveServerAndToken -- except this tool has no login flow or credential store (see
// docs/design-keyorix-migrate.md's "PAT provisioning UX" open question): the operator always
// supplies a PAT explicitly.
func resolveServerAndToken(flagServer, flagToken string) (serverURL, token string, err error) {
	serverURL = flagServer
	if serverURL == "" {
		serverURL = os.Getenv("KEYORIX_SERVER")
	}
	token = flagToken
	if token == "" {
		token = os.Getenv("KEYORIX_TOKEN")
	}
	if serverURL == "" {
		return "", "", fmt.Errorf("no server configured: use --server or $KEYORIX_SERVER")
	}
	if token == "" {
		return "", "", fmt.Errorf("no token configured: use --token or $KEYORIX_TOKEN (a Keyorix Personal Access Token)")
	}
	return serverURL, token, nil
}

// newAPIClient builds a generated client against serverURL, attaching an Authorization header
// -- identical pattern to cli/cmd/client.go's newAPIClient (ADR-108's REST+PAT precedent).
func newAPIClient(serverURL, token string) (*apiclient.ClientWithResponses, error) {
	return apiclient.NewClientWithResponses(serverURL, apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
}
