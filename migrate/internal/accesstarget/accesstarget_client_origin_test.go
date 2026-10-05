// accesstarget_client_origin_test.go — #2545's fix extended to the access-model migration: a
// role/machine identity/grant/OIDC binding apply-access creates was indistinguishable in the
// audit trail from one a human created by hand, the same gap internal/target already closed
// for secret values. Every write here now sends core.ClientOriginHeader naming this tool and
// (via accessplan.WithSourceOrigin) the exact Vault policy/role it came from.
package accesstarget

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
)

// TestWrites_SendClientOriginHeader drives all five KeyorixWriter write calls and asserts each
// one sent clientOriginHeader naming keyorix-migrate and the source locator.
func TestWrites_SendClientOriginHeader(t *testing.T) {
	got := map[string]string{}
	record := func(key string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			got[key] = r.Header.Get(clientOriginHeader)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		record("create_role")(w, r)
		writeJSONStatus(w, http.StatusCreated, `{"data":{"role":{"id":5,"name":"vault-migrated-read"},"permissions":[]}}`)
	})
	mux.HandleFunc("/api/v1/projects/1/machine-identities", func(w http.ResponseWriter, r *http.Request) {
		record("create_machine")(w, r)
		writeJSONStatus(w, http.StatusCreated, `{"data":{"machine_identity":{"id":42,"name":"vault-approle-ci","project_id":1,"state":"active"}}}`)
	})
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/tokens", func(w http.ResponseWriter, r *http.Request) {
		record("issue_credential")(w, r)
		writeJSONStatus(w, http.StatusCreated, `{"data":{"token":"kx_machine_abc123","id":9,"prefix":"kx_machine_ab"}}`)
	})
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/roles", func(w http.ResponseWriter, r *http.Request) {
		record("grant_role")(w, r)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/oidc-bindings", func(w http.ResponseWriter, r *http.Request) {
		record("create_binding")(w, r)
		writeJSONStatus(w, http.StatusCreated, `{"data":{"id":1,"issuer":"https://k8s.example.com","subject":"sa"}}`)
	})
	c := fakeKeyorix(t, mux)

	const ref = "approle-role:ci-deployer"
	ctx := accessplan.WithSourceOrigin(context.Background(), ref)

	if _, err := c.CreateRole(ctx, "vault-migrated-read", "d", []string{"secrets.read"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if _, err := c.CreateMachineIdentity(ctx, 1, "vault-approle-ci", "service", "d"); err != nil {
		t.Fatalf("CreateMachineIdentity: %v", err)
	}
	if _, err := c.IssueMachineCredential(ctx, 1, 42, "migrated-from-vault"); err != nil {
		t.Fatalf("IssueMachineCredential: %v", err)
	}
	if err := c.GrantMachineRole(ctx, 1, 0, 42, 5); err != nil {
		t.Fatalf("GrantMachineRole: %v", err)
	}
	if err := c.CreateOIDCBinding(ctx, 1, 42, "https://k8s.example.com", "sa"); err != nil {
		t.Fatalf("CreateOIDCBinding: %v", err)
	}

	for _, key := range []string{"create_role", "create_machine", "issue_credential", "grant_role", "create_binding"} {
		h := got[key]
		if !strings.HasPrefix(h, "keyorix-migrate/") || !strings.Contains(h, "source="+ref) {
			t.Errorf("%s: %s = %q, want keyorix-migrate/<ver> source=%s", key, clientOriginHeader, h, ref)
		}
	}
}

// TestWrites_NoSourceOrigin_StillSendsToolName covers the case where a write runs without a
// WithSourceOrigin tag (shouldn't happen via Apply, but the header must degrade gracefully, not
// send an empty/malformed value).
func TestWrites_NoSourceOrigin_StillSendsToolName(t *testing.T) {
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(clientOriginHeader)
		writeJSONStatus(w, http.StatusCreated, `{"data":{"role":{"id":5,"name":"x"},"permissions":[]}}`)
	})
	c := fakeKeyorix(t, mux)
	if _, err := c.CreateRole(context.Background(), "x", "d", []string{"secrets.read"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if !strings.HasPrefix(got, "keyorix-migrate/") || strings.Contains(got, "source=") {
		t.Fatalf("%s = %q, want keyorix-migrate/<ver> with no source= suffix", clientOriginHeader, got)
	}
}
