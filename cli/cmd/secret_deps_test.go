// secret_deps_test.go — regression test for `secret deps rm`'s success-status
// check: the real server responds 200 with a body (sendSuccess), not 204, for
// RemoveSecretDependency (server/http/handlers/secret_dependencies.go) -- this
// command previously required 204, so it reported failure on every successful
// removal. Found while writing scripts/e2e/journeys/journey8, which drives
// `secret deps rm` through the real CLI/server and hit this on every call.
package cmd

import (
	"fmt"
	"net/http"
	"testing"
)

func TestRunSecretDepsRemove_SucceedsOnRealServerStatusCode(t *testing.T) {
	srv := secretOpsServer(t,
		secretOpsRoute{http.MethodDelete, "/api/v1/secrets/1/dependencies/9", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"success":true,"data":{"removed":true},"message":"Dependency removed"}`)
		}},
	)
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := secretDepsRemoveCmd.RunE(secretDepsRemoveCmd, []string{"1", "9"}); err != nil {
			t.Fatalf("secret deps rm: %v", err)
		}
	})
	if !containsAll(out, "Removed dependency edge 9 from secret 1") {
		t.Fatalf("output = %q", out)
	}
}
