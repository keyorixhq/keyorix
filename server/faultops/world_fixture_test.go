// world_fixture_test.go verifies each newFaultWorld fixture gap this PR closes
// works standalone, before any opCatalog entry (PR B's job) depends on it —
// the fixtures are lazy (built on first use, see each ensure* method's own doc
// comment), so nothing in the existing opCatalog exercises them yet.
package faultops

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestWorldFixture_Encryption(t *testing.T) {
	w := newFaultWorld(t, nil)
	if err := w.ensureEncryption(t); err != nil {
		t.Fatalf("ensureEncryption: %v", err)
	}
	if !w.core.SecretValueEncryptionActive() {
		t.Fatal("secret-value encryption not active after ensureEncryption")
	}
	// Calling twice must be safe (sync.Once-guarded) and not re-derive the KEK.
	if err := w.ensureEncryption(t); err != nil {
		t.Fatalf("ensureEncryption (second call): %v", err)
	}
}

func TestWorldFixture_WebAuthn(t *testing.T) {
	w := newFaultWorld(t, nil)
	if !w.core.WebAuthnEnabled() {
		t.Fatal("WebAuthnEnabled() is false after newFaultWorld — SetWebAuthn was not wired")
	}
}

// TestWorldFixture_BreakGlass exercises the real end-to-end business logic
// (not just "is the policy set") — a project the admin is a member of,
// activating break-glass, and getting back a real activation — to prove the
// EmergencyRole/TTL fixture actually satisfies core.ActivateBreakGlass's own
// validation (install-wide-admin refusal, roles.assign refusal, TTL bounds).
func TestWorldFixture_BreakGlass(t *testing.T) {
	w := newFaultWorld(t, nil)
	ctx := context.Background()

	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fixture-bg-project"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if st/100 != 2 {
		t.Fatalf("CreateProject: HTTP %d: %s", st, body)
	}
	var proj struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &proj); err != nil || proj.Data.ID == 0 {
		t.Fatalf("decoding CreateProject response: %v (body=%s)", err, body)
	}

	roleID, err := createRoleForFuzz(ctx, w)
	if err != nil {
		t.Fatalf("createRoleForFuzz: %v", err)
	}
	if err := w.faulty.AssignRole(ctx, 1, roleID, coreStorage.Scope{ProjectID: proj.Data.ID}); err != nil {
		t.Fatalf("AssignRole (membership): %v", err)
	}

	if _, err := w.core.ActivateBreakGlass(ctx, proj.Data.ID, 1, "fixture verification justification", ""); err != nil {
		t.Fatalf("ActivateBreakGlass: %v", err)
	}
}

// TestWorldFixture_DynamicSecretsEngineFactory proves the factory itself is
// wired (core.dynamicEngine, called early inside CreateDynamicSecretConfig,
// returns "no engine factory configured" verbatim when it is nil — see
// internal/core/service.go — and nothing else produces that exact string).
// It deliberately does NOT require CreateDynamicSecretConfig to fully
// succeed: a real reachable Postgres target is PR B's concern when it wires
// an actual dynamic-secrets operation, not this fixture-only PR's.
func TestWorldFixture_DynamicSecretsEngineFactory(t *testing.T) {
	w := newFaultWorld(t, nil)
	ctx := context.Background()
	_, err := w.core.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name: "fixture-check", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
		AdminDSN: "postgres://user:pass@example.com:5432/db", ActorID: 1,
	})
	if err != nil && strings.Contains(err.Error(), "no engine factory configured") {
		t.Fatalf("dynamic-secrets engine factory not wired: %v", err)
	}
}
