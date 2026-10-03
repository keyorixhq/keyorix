package accesstarget

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func writeJSONStatus(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestCreateRole(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusCreated, `{"data":{"role":{"id":5,"name":"vault-migrated-read"},"permissions":[]}}`)
	})
	c := fakeKeyorix(t, mux)
	id, err := c.CreateRole(context.Background(), "vault-migrated-read", "migrate.source-id: k1", []string{"secrets.read"})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if id != 5 {
		t.Fatalf("id = %d, want 5", id)
	}
}

func TestCreateRole_Conflict(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusConflict, `{"error":{"message":"role already exists"}}`)
	})
	c := fakeKeyorix(t, mux)
	_, err := c.CreateRole(context.Background(), "x", "d", []string{"secrets.read"})
	if err == nil {
		t.Fatal("expected an error on 409")
	}
}

func TestCreateMachineIdentity(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusCreated, `{"data":{"machine_identity":{"id":42,"name":"vault-approle-ci","project_id":1,"state":"pending"}}}`)
	})
	c := fakeKeyorix(t, mux)
	id, err := c.CreateMachineIdentity(context.Background(), 1, "vault-approle-ci", "service", "migrate.source-id: m1")
	if err != nil {
		t.Fatalf("CreateMachineIdentity: %v", err)
	}
	if id != 42 {
		t.Fatalf("id = %d, want 42", id)
	}
}

func TestIssueMachineCredential(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusCreated, `{"data":{"token":"kx_machine_abc123","id":9,"prefix":"kx_machine_ab"}}`)
	})
	c := fakeKeyorix(t, mux)
	token, err := c.IssueMachineCredential(context.Background(), 1, 42, "migrated-from-vault")
	if err != nil {
		t.Fatalf("IssueMachineCredential: %v", err)
	}
	if token != "kx_machine_abc123" {
		t.Fatalf("token = %q", token)
	}
}

func TestGrantMachineRole_Write(t *testing.T) {
	var gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/roles", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 128)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	})
	c := fakeKeyorix(t, mux)
	if err := c.GrantMachineRole(context.Background(), 1, 10, 42, 5); err != nil {
		t.Fatalf("GrantMachineRole: %v", err)
	}
	if !strings.Contains(gotBody, `"environment_id":10`) || !strings.Contains(gotBody, `"role_id":5`) {
		t.Fatalf("request body = %q, want environment_id and role_id both present", gotBody)
	}
}

func TestCreateOIDCBinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/oidc-bindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusCreated, `{"data":{"id":1,"issuer":"https://k8s.example.com","subject":"system:serviceaccount:prod:deployer"}}`)
	})
	c := fakeKeyorix(t, mux)
	if err := c.CreateOIDCBinding(context.Background(), 1, 42, "https://k8s.example.com", "system:serviceaccount:prod:deployer"); err != nil {
		t.Fatalf("CreateOIDCBinding: %v", err)
	}
}
