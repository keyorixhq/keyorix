package healthscan

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// canaryValue is a distinctive marker planted at a Vault KV v2 *data* path in the fake server
// below — the shape of a real secret value (a KV field, a token, an API key). It must never
// appear anywhere this tool writes, in any format: G1's whole premise ("safe to run against a
// PRODUCTION Vault") depends on that being true by construction, not by review discipline.
const canaryValue = "s.CANARY-9f3a1e7c-do-not-leak-me-AKIAFAKEKEYXXXXXXXXX"

// fakeVaultServer stands up an httptest server shaped like a real Vault: a couple of sys/*
// endpoints a healthscan check might plausibly read, AND a KV v2 secret whose data payload
// carries canaryValue — proving the redaction guarantee against a server that WOULD leak the
// canary if any check (now or added later) ever read secret data instead of metadata.
func fakeVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.15.6","cluster_name":"vault-cluster-canary-test"}`))
	})
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sealed":false,"type":"shamir"}`))
	})
	// A KV v2 secret data path. A GET here returns the canary as a real secret VALUE, exactly
	// the shape docs/vault-health-scan.md forbids healthscan from ever reading ("Never read KV
	// data, only metadata"). No check registered in this test touches this path — that's the
	// property under test.
	mux.HandleFunc("/v1/secret/data/prod/db-password", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"data":{"password":"` + canaryValue + `"},"metadata":{"version":3}}}`))
	})
	// The corresponding metadata-only path (what a real check, e.g. G2's "secrets not updated in
	// > 365 days", is allowed to read) never carries the canary.
	mux.HandleFunc("/v1/secret/metadata/prod/db-password", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"current_version":3,"updated_time":"2024-01-01T00:00:00Z"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestRedaction_CanaryNeverAppearsInAnyOutputFormat is G1's redaction guard. It runs a small,
// test-local set of representative checks (G1 ships with an empty production registry — G2
// populates it) against fakeVaultServer, then asserts canaryValue appears in none of the three
// output formats. One of the checks deliberately reads the KV metadata path (the one real checks
// are allowed to touch); none read the data path — proving the guarantee holds for the read
// pattern real checks will use, not just for an empty check list.
func TestRedaction_CanaryNeverAppearsInAnyOutputFormat(t *testing.T) {
	srv := fakeVaultServer(t)

	c := &Client{addr: srv.URL, token: "t", hc: srv.Client()}

	checks := []Check{
		{ID: "sys-health", Title: "Vault health", Fn: func(ctx context.Context, c *Client) Result {
			status, body, err := c.Get(ctx, "sys/health")
			if err != nil {
				return Result{Err: err}
			}
			return Result{Finding: &Finding{ID: "sys-health", Title: "Vault health", Severity: SeverityInfo, Evidence: string(body) + " status=" + http.StatusText(status)}}
		}},
		{ID: "kv-metadata-age", Title: "Secret age", Fn: func(ctx context.Context, c *Client) Result {
			_, body, err := c.Get(ctx, "secret/metadata/prod/db-password")
			if err != nil {
				return Result{Err: err}
			}
			return Result{Finding: &Finding{ID: "kv-metadata-age", Title: "Secret age", Severity: SeverityLow, Evidence: string(body)}}
		}},
		{ID: "denied-path", Title: "Something the token can't read", Fn: func(ctx context.Context, c *Client) Result {
			return Result{NotChecked: &NotChecked{ID: "denied-path", Reason: "permission denied", PolicyLine: `path "sys/some/thing" { capabilities = ["read"] }`}}
		}},
	}

	r := RunChecks(context.Background(), c, srv.URL, "keyorix-migrate dev", checks)

	var jsonBuf, mdBuf, htmlBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, r); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if err := WriteMarkdown(&mdBuf, r); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if err := WriteHTML(&htmlBuf, r); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	for name, buf := range map[string]*bytes.Buffer{"json": &jsonBuf, "markdown": &mdBuf, "html": &htmlBuf} {
		if strings.Contains(buf.String(), canaryValue) {
			t.Fatalf("%s output leaked the canary secret value:\n%s", name, buf.String())
		}
	}

	// Sanity: prove the assertion above is meaningful by confirming the canary really does exist
	// at the data path this test never reads — a redaction test that can't fail is worthless.
	_, dataBody, err := c.Get(context.Background(), "secret/data/prod/db-password")
	if err != nil {
		t.Fatalf("sanity GET of data path: %v", err)
	}
	if !strings.Contains(string(dataBody), canaryValue) {
		t.Fatal("sanity check failed: the fake server's data path doesn't even carry the canary — this test would pass vacuously")
	}
}
