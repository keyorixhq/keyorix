package http

// Fixture-survival checks for FuzzOpenAPIStateful (#4134 review MEDIUM-1).
//
// The fuzzer's world (projects, the canary secret, role grants, session tokens) is built
// once per process, but the operation set includes destructive calls (deleteProject,
// authLogout, authRefresh, role/grant removal, ...). Without a per-iteration check the
// world was destroyed within seconds, which made the canary oracle (4) and every
// authenticated-principal path vacuous. osFixturesIntact is the machine-checked statement
// of "the world still looks the way the oracles assume"; osRunIteration calls it after
// every iteration and rebuilds the world when it fails.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// osFixturesIntact returns nil when the seeded world is still usable by the oracles, else
// an error naming the first broken fixture. It checks: the seeded projects, environments,
// roles and users exist; both seeded secrets (the canary among them) exist and are active;
// the three project-A grants (viewer, project admin, expired) still exist; and every
// authenticated principal's token is still accepted (not 401) by the real router.
//
// Does NOT verify: the canary's stored value (it is read back through the API by oracle 4's
// own traffic, not here) or machine-identity role assignments beyond token acceptance.
func osFixturesIntact(w *osWorld) error {
	count := func(model any, query string, args ...any) (int64, error) {
		var n int64
		err := w.db.Model(model).Where(query, args...).Count(&n).Error
		return n, err
	}
	for _, c := range []struct {
		name  string
		model any
		ids   []uint
	}{
		{"project", &models.Project{}, w.seedPools["projects"]},
		{"environment", &models.Environment{}, w.seedPools["environments"]},
		{"role", &models.Role{}, w.seedPools["roles"]},
		{"user", &models.User{}, w.seedPools["users"]},
	} {
		n, err := count(c.model, "id IN ?", c.ids)
		if err != nil {
			return fmt.Errorf("count %ss: %w", c.name, err)
		}
		if int(n) != len(c.ids) {
			return fmt.Errorf("%d of %d seeded %ss survive", n, len(c.ids), c.name)
		}
	}
	n, err := count(&models.SecretNode{}, "id IN ? AND (status = ? OR status = '')", w.seedPools["secrets"], "active")
	if err != nil {
		return fmt.Errorf("count secrets: %w", err)
	}
	if int(n) != len(w.seedPools["secrets"]) {
		return fmt.Errorf("%d of %d seeded secrets survive as active (canary secret included)", n, len(w.seedPools["secrets"]))
	}

	// users = {admin, norole, viewer, projadmin, expired}; roles = {viewer, projadmin};
	// projects[0] = project A.
	u, r, pA := w.seedPools["users"], w.seedPools["roles"], w.seedPools["projects"][0]
	for _, g := range []struct {
		name       string
		user, role uint
	}{
		{"viewer", u[2], r[0]}, {"projadmin", u[3], r[1]}, {"expired", u[4], r[0]},
	} {
		n, err := count(&models.UserRole{}, "user_id = ? AND role_id = ? AND project_id = ?", g.user, g.role, pA)
		if err != nil {
			return fmt.Errorf("count %s grant: %w", g.name, err)
		}
		if n != 1 {
			return fmt.Errorf("%s grant missing (user=%d role=%d project=%d)", g.name, g.user, g.role, pA)
		}
	}

	for p := osPrincNoRole; p < osNumPrincipals; p++ {
		if w.tokens[p] == "" {
			continue // machine token could not be issued at build time (logged there)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		req.Header.Set("Authorization", "Bearer "+w.tokens[p])
		if rec := osExec(w, req); rec.Code == http.StatusUnauthorized {
			return fmt.Errorf("principal %d token rejected with 401", p)
		}
	}
	return nil
}

func osTestWorld(t *testing.T) *osWorld {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	t.Cleanup(i18n.ResetForTesting)
	osLoadSpec(t)
	return osBuildWorld(t)
}

func osOpIndex(t *testing.T, opID string) int {
	t.Helper()
	for i := range osOps {
		if osOps[i].opID == opID {
			return i
		}
	}
	t.Fatalf("operation %s not in spec", opID)
	return -1
}

// A freshly built world must pass its own check (guards against a check that is always red).
func TestOpenAPIStateful_FixturesIntactOnFreshWorld(t *testing.T) {
	w := osTestWorld(t)
	if err := osFixturesIntact(w); err != nil {
		t.Fatalf("fresh world not intact: %v", err)
	}
}

// Destroying fixtures must be detected, and the next iteration must leave an intact world.
// Red on fe1b018f: osRunIteration did not look at the world at all.
func TestOpenAPIStateful_FixturesSurviveIterations(t *testing.T) {
	w := osTestWorld(t)
	ctx := context.Background()

	// Destroy what the oracles depend on: the canary secret and a principal's session.
	canary := w.seedPools["secrets"][0]
	if err := w.db.Delete(&models.SecretNode{}, canary).Error; err != nil {
		t.Fatalf("delete canary secret: %v", err)
	}
	if err := w.c.Logout(ctx, w.tokens[osPrincViewer]); err != nil {
		t.Fatalf("logout viewer: %v", err)
	}
	if osFixturesIntact(w) == nil {
		t.Fatal("osFixturesIntact did not detect a deleted canary secret and a logged-out viewer")
	}

	osRunIteration(t, w, []byte{}) // empty program: one harmless step

	if err := osFixturesIntact(w); err != nil {
		t.Fatalf("world not restored after iteration: %v", err)
	}
}

// authRefresh invalidates the old token; the harness must adopt the new one instead of
// leaving that principal 401 for the rest of the run, and must not need a rebuild for it.
// Red on fe1b018f: the refreshed token was discarded.
func TestOpenAPIStateful_RefreshedTokenIsCaptured(t *testing.T) {
	w := osTestWorld(t)
	idx := osOpIndex(t, "authRefresh")
	old := w.tokens[osPrincGlobalAdmin]
	dbBefore := w.db

	// byte0 = principal, byte1 = step count-1 (1 step), u16 = op index, byte = mode 0.
	osRunIteration(t, w, []byte{osPrincGlobalAdmin, 0, byte(idx >> 8), byte(idx), 0})

	if w.tokens[osPrincGlobalAdmin] == old {
		t.Fatal("admin token unchanged after authRefresh: refreshed token was not captured")
	}
	if w.db != dbBefore {
		t.Fatal("world was rebuilt for a plain authRefresh; the new token should have been adopted")
	}
	if err := osFixturesIntact(w); err != nil {
		t.Fatalf("world not intact after authRefresh: %v", err)
	}
}
