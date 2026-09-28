// Integration test against a real Vault (or OpenBao) dev server — SESSION-G4's requirement:
// "runs the full scan against the existing CI Vault and OpenBao dev containers and asserts: no
// write request was made (count methods at the wrapper), report generated in all 3 formats, no
// secret value from seeded KV data appears." Skips (not fails) when $VAULT_ADDR is unset,
// matching internal/vaultsource/vault_integration_test.go's own convention — the migrate CI job
// (.github/workflows/ci.yml) sets it via a matrix of vault/openbao service containers, so a skip
// is only expected locally.
//
// To run locally: `docker run -d -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root-token
// -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 hashicorp/vault:1.15`, then
// `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root-token go test ./... -run Integration`.
// Verified directly against both a real Vault 1.15 dev server and a real OpenBao 2.0 dev server
// before this test was written (not just designed against documentation) — see this PR's
// description for the actual command transcripts and rendered report excerpts.
package healthscan

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func requireVaultEnv(t *testing.T) (addr, token string) {
	t.Helper()
	addr = os.Getenv("VAULT_ADDR")
	if addr == "" {
		t.Skip("VAULT_ADDR not set — skipping Vault integration test (see this file's doc comment to run locally)")
	}
	token = os.Getenv("VAULT_TOKEN")
	if token == "" {
		t.Fatal("VAULT_ADDR is set but VAULT_TOKEN is not")
	}
	return addr, token
}

// methodCountingTransport records every HTTP method that actually reached the wire — the
// strongest form of "no write request was made" this test can offer: it doesn't trust
// client.go's own request() allowlist (that's what client_test.go's unit-level
// TestRequest_RejectsWriteMethods already proves), it independently observes real traffic
// against a real server.
type methodCountingTransport struct {
	base    http.RoundTripper
	methods map[string]int
}

func (t *methodCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.methods[req.Method]++
	return t.base.RoundTrip(req)
}

// vaultAdminPut seeds a KV v2 secret directly via the Vault HTTP API, independent of the Client
// under test — this test's own fixture setup, not something healthscan itself does.
func vaultAdminPut(t *testing.T, addr, token, path, canaryValue string) {
	t.Helper()
	body := strings.NewReader(`{"data":{"password":"` + canaryValue + `"}}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, addr+"/v1/secret/data/"+path, body)
	if err != nil {
		t.Fatalf("build admin seed request: %v", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("seed KV secret: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		t.Fatalf("seed KV secret returned HTTP %d", resp.StatusCode)
	}
}

// TestIntegration_FullScanAgainstRealServer is SESSION-G4's own integration test, run once per
// CI matrix leg (vault, openbao — .github/workflows/ci.yml's `migrate` job).
func TestIntegration_FullScanAgainstRealServer(t *testing.T) {
	addr, token := requireVaultEnv(t)

	const canaryValue = "s.CI-INTEGRATION-CANARY-do-not-leak-me-AKIAFAKEKEYXXXXXXXXX"
	vaultAdminPut(t, addr, token, "healthscan-integration-fixture", canaryValue)

	counting := &methodCountingTransport{base: http.DefaultTransport, methods: map[string]int{}}
	c := &Client{addr: strings.TrimRight(addr, "/"), token: token, hc: &http.Client{Timeout: 30 * time.Second, Transport: counting}}

	report := Run(context.Background(), c, addr, "keyorix-migrate integration-test")

	// "no write request was made (count methods at the wrapper)": every real HTTP request this
	// client issued (across all ~19 registered checks) must have been a GET. LIST is
	// wire-encoded as GET+?list=true (client.go's request()), so a fully read-only run never
	// touches the wire with anything else.
	for method, count := range counting.methods {
		if method != http.MethodGet {
			t.Errorf("wrapper issued a non-GET request: %s x%d — the read-only guarantee was violated against a real server", method, count)
		}
	}
	if counting.methods[http.MethodGet] == 0 {
		t.Fatal("no requests were observed at all — this test isn't actually exercising the client (check the transport wiring)")
	}

	// "report generated in all 3 formats".
	var jsonBuf, mdBuf, htmlBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, report); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if err := WriteMarkdown(&mdBuf, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if err := WriteHTML(&htmlBuf, report); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if jsonBuf.Len() == 0 || mdBuf.Len() == 0 || htmlBuf.Len() == 0 {
		t.Fatal("one or more report formats came back empty")
	}

	// "no secret value from seeded KV data appears" — the canary this test planted must not
	// leak into any output, even though real checks (secret-staleness, migration-readiness) did
	// read metadata about the exact path it lives at.
	for name, buf := range map[string]*bytes.Buffer{"json": &jsonBuf, "markdown": &mdBuf, "html": &htmlBuf} {
		if strings.Contains(buf.String(), canaryValue) {
			t.Fatalf("%s output leaked the seeded canary secret value", name)
		}
	}

	// Sanity: a real scan against a Vault dev server (root token, no audit device, TLS disabled
	// in dev mode, single-share shamir) should find real, severe findings — a report with zero
	// findings here would mean the checks silently no-op'd against a real server rather than
	// actually running.
	if len(report.Findings) == 0 {
		t.Fatal("expected at least one finding against a Vault dev server — got none, which suggests the checks didn't actually run")
	}
	if report.Score == 100 {
		t.Error("a Vault dev server (root token, no audit device) scoring a perfect 100 suggests the risk checks aren't actually evaluating real server state")
	}
	if report.MigrationReadiness == nil {
		t.Error("expected MigrationReadiness to be populated against a real server")
	} else if report.MigrationReadiness.KVTopLevelSecrets < 1 {
		t.Error("expected the seeded fixture secret to be counted in migration readiness")
	}
}
