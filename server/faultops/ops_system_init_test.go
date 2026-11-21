package faultops

import (
	"context"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// POST /system/init (PARTIAL-COMMIT-TAILS-NOV-3 item 1, #3225): the first-admin
// bootstrap, driven through the real unauthenticated route with the bootstrap
// token. Every world is bootstrapped during its build (newFaultWorld), so Setup
// first puts it back into the one state in which the route creates anything: a
// pre-marker install whose every user (and the default project) was
// soft-deleted, the state systemInitializedKey's own doc comment describes
// (internal/core/auth_bootstrap.go). It soft-deletes rather than wipes, so the
// core's in-memory caches (audit-chain head, role permissions) stay consistent
// with the rows; the seeded catalog stays and the bootstrap reuses it
// (idempotent seeding). The bootstrap token is single-use and the world's own
// bootstrap cleared it, so Setup re-arms it. Fixed timestamp: oracle (a) compares
// with an independently built reference world.
const (
	systemInitToken    = "fault-fuzz-bootstrap"
	systemInitUsername = "fuzzinit"
	systemInitPassword = "Kx7!Fuzz-Init-Pwd#2026"
)

var systemInitDeletedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func systemInitSetup(ctx context.Context, w *faultWorld) (any, error) {
	db := w.db.WithContext(ctx)
	if err := db.Model(&models.User{}).Where("deleted_at IS NULL").Update("deleted_at", systemInitDeletedAt).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&models.Project{}).Where("deleted_at IS NULL").Update("deleted_at", systemInitDeletedAt).Error; err != nil {
		return nil, err
	}
	if err := db.Where("key = ?", "system_initialized").Delete(&models.SystemMetadata{}).Error; err != nil {
		return nil, err
	}
	w.core.SetBootstrapToken(systemInitToken)
	return nil, nil
}

func systemInitExecute(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
	st, body, err := httpJSONAs(ctx, w, "", http.MethodPost, "/system/init", map[string]any{
		"username": systemInitUsername, "email": systemInitUsername + "@example.com",
		"password": systemInitPassword, "bootstrap_token": systemInitToken,
	})
	if err != nil {
		return opResult{}, err
	}
	return httpResult(st, body), nil
}

func init() {
	// Setup soft-deletes every user, the guard's admin included.
	utcGuardSeedSkipOps["REST POST /system/init"] = "deprovisions every user, the guard admin included (ops_system_init_test.go)"
	registerOps("system_init", operation{Key: "REST POST /system/init", Setup: systemInitSetup, Execute: systemInitExecute})
	registerOverrides("system_init", map[string]overrideEntry{
		"REST POST /system/init": {StatusFuzzed, "PARTIAL-COMMIT-TAILS-NOV-3 item 1 (#3225): Setup returns the world to a pre-marker, fully deprovisioned install (ops_system_init_test.go)"},
	})
}
