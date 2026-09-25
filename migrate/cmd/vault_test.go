package cmd

import (
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
)

// TestSanitizeSecretName_DistinctVaultPathsCanCollide proves sanitizeSecretName is lossy: "/"
// and a literal "-" both collapse to the same separator, so two genuinely distinct Vault KV
// paths can sanitize to the identical Keyorix secret name. Before this review round, vaultsource
// was believed immune to the intra-batch name collision cloud sources need --split-json to
// trigger — "KV paths are unique by construction" is true, but says nothing about their
// SANITIZED names also being unique, which this test shows they are not.
func TestSanitizeSecretName_DistinctVaultPathsCanCollide(t *testing.T) {
	pathA, pathB := "a/b/c", "a/b-c"
	nameA, nameB := sanitizeSecretName(pathA), sanitizeSecretName(pathB)
	if nameA != nameB {
		t.Fatalf("sanitizeSecretName(%q)=%q, sanitizeSecretName(%q)=%q, want them equal (that's the collision this test demonstrates)", pathA, nameA, pathB, nameB)
	}
}

// TestRunVault_SanitizationCollisionIsCaughtNotSilentlyDoubleCreated is the "same guard for the
// Vault source" case: runVault now runs planEntries through splitIntraBatchNameCollisions (the
// same guard cmd/aws.go, cmd/azure.go, and cmd/gcp.go use) before calling plan.BuildPlan, exactly
// mirroring the shape runVault itself builds planEntries in (sanitizeSecretName(path), a
// plan.SourceID keyed on addr/mount/path/field) — this reproduces that shape directly with two
// colliding paths rather than invoking runVault's full CLI/network flow.
func TestRunVault_SanitizationCollisionIsCaughtNotSilentlyDoubleCreated(t *testing.T) {
	const addr, mount = "https://vault.example.com", "secret"
	paths := []string{"a/b/c", "a/b-c"} // both sanitize to "a-b-c"

	planEntries := make([]plan.Entry, 0, len(paths))
	for i, p := range paths {
		planEntries = append(planEntries, plan.Entry{
			SourceKind: "vault",
			Path:       "vault:" + mount + "/" + p,
			Name:       sanitizeSecretName(p),
			Value:      "v" + string(rune('1'+i)),
			SourceID:   plan.SourceID(addr, mount, p, "value"),
		})
	}
	if planEntries[0].Name != planEntries[1].Name {
		t.Fatalf("test setup assumption broken: names %q and %q are not equal", planEntries[0].Name, planEntries[1].Name)
	}

	unique, collided := splitIntraBatchNameCollisions(planEntries)
	if len(unique) != 1 {
		t.Fatalf("unique = %+v, want 1 (only one of the two colliding Vault paths wins)", unique)
	}
	if len(collided) != 1 {
		t.Fatalf("collided = %+v, want 1 (the other path flagged as a conflict, never silently double-created)", collided)
	}
	if collided[0].Outcome != plan.Conflict {
		t.Errorf("collided[0].Outcome = %q, want Conflict", collided[0].Outcome)
	}
	if collided[0].Reason == "" {
		t.Error("collided[0] has no Reason explaining the collision")
	}
}
