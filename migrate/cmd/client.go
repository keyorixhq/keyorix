package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
)

// resolveServer applies the precedence flag > env var. Not a credential (a URL, not a
// secret) so it has no --*-file counterpart, unlike the token (resolveCredential).
func resolveServer(flagServer string) (string, error) {
	serverURL := flagServer
	if serverURL == "" {
		serverURL = os.Getenv("KEYORIX_SERVER")
	}
	if serverURL == "" {
		return "", fmt.Errorf("no server configured: use --server or $KEYORIX_SERVER")
	}
	return serverURL, nil
}

// newAPIClient builds a generated client against serverURL, attaching an Authorization header
// -- identical pattern to cli/cmd/client.go's newAPIClient (ADR-108's REST+PAT precedent).
func newAPIClient(serverURL, token string) (*apiclient.ClientWithResponses, error) {
	return apiclient.NewClientWithResponses(serverURL, apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
}
