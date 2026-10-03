package accesstarget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
)

func fakeKeyorix(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	api, err := apiclient.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	return New(api)
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func TestListProjects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"projects":[{"id":1,"name":"team-a"},{"id":2,"name":"team-b"}]}}`)
	})
	c := fakeKeyorix(t, mux)
	projects, err := c.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 2 || projects[0].Name != "team-a" {
		t.Fatalf("projects = %+v", projects)
	}
}

func TestListEnvironments(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/environments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"environments":[{"id":10,"name":"prod","project_id":1}]}}`)
	})
	c := fakeKeyorix(t, mux)
	envs, err := c.ListEnvironments(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	if len(envs) != 1 || envs[0].Name != "prod" || envs[0].ID != 10 {
		t.Fatalf("envs = %+v", envs)
	}
}

func TestRoleDescriptionByName_Found(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles/by-name", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"id":5,"name":"vault-migrated-read","description":"migrate.source-id: abc123"}}`)
	})
	c := fakeKeyorix(t, mux)
	desc, found, err := c.RoleDescriptionByName(context.Background(), "vault-migrated-read")
	if err != nil {
		t.Fatalf("RoleDescriptionByName: %v", err)
	}
	if !found || desc != "migrate.source-id: abc123" {
		t.Fatalf("found=%v desc=%q", found, desc)
	}
}

func TestRoleDescriptionByName_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles/by-name", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, `{"error":{"message":"not found"}}`)
	})
	c := fakeKeyorix(t, mux)
	_, found, err := c.RoleDescriptionByName(context.Background(), "nope")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false on 404")
	}
}

func TestMachineHasRoleGrant(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"machine_identities":[{"id":42,"name":"vault-approle-ci","project_id":1}]}}`)
	})
	mux.HandleFunc("/api/v1/projects/1/machine-identities/42/roles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"roles":[{"id":9,"name":"vault-migrated-read"}]}}`)
	})
	c := fakeKeyorix(t, mux)
	has, err := c.MachineHasRoleGrant(context.Background(), 1, "vault-approle-ci", "vault-migrated-read")
	if err != nil {
		t.Fatalf("MachineHasRoleGrant: %v", err)
	}
	if !has {
		t.Fatal("expected has=true")
	}
	has2, err := c.MachineHasRoleGrant(context.Background(), 1, "vault-approle-ci", "some-other-role")
	if err != nil {
		t.Fatalf("MachineHasRoleGrant: %v", err)
	}
	if has2 {
		t.Fatal("expected has=false for an ungranted role name")
	}
}

func TestMachineHasRoleGrant_MachineDoesNotExistYet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"machine_identities":[]}}`)
	})
	c := fakeKeyorix(t, mux)
	has, err := c.MachineHasRoleGrant(context.Background(), 1, "does-not-exist", "r")
	if err != nil || has {
		t.Fatalf("has=%v err=%v, want false/nil", has, err)
	}
}

func TestMachineHasOIDCBinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/machine-identities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"machine_identities":[{"id":7,"name":"vault-k8s-prod-deployer","project_id":1}]}}`)
	})
	mux.HandleFunc("/api/v1/projects/1/machine-identities/7/oidc-bindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"data":{"bindings":[{"id":1,"issuer":"https://k8s.example.com","subject":"system:serviceaccount:prod:deployer"}]}}`)
	})
	c := fakeKeyorix(t, mux)
	has, err := c.MachineHasOIDCBinding(context.Background(), 1, "vault-k8s-prod-deployer", "https://k8s.example.com", "system:serviceaccount:prod:deployer")
	if err != nil || !has {
		t.Fatalf("has=%v err=%v, want true/nil", has, err)
	}
}
