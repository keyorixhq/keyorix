package accessplan

import (
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// The categories are spelled as literals (not the named constants) so these tests also compile
// against the pre-fix code: their red run fails on the assertion, not on a missing symbol.
const (
	wantNarrowerCategory UnmappableCategory = "path-narrower-than-scope"
	wantMetadataCategory UnmappableCategory = "metadata-only"
)

// widenMapper mirrors the migration demo (scripts/demo/vault-migration-demo.sh): one KV v2
// mount, a KV v1 mount, and the default-convention projects testMapper uses.
func widenMapper(t *testing.T, overrides ...string) *PathMapper {
	t.Helper()
	return testMapper(t, overrides...)
}

func buildOne(t *testing.T, m *PathMapper, path string, caps ...string) Item {
	t.Helper()
	items := BuildPolicyItems([]healthscan.Policy{{Name: "p", Blocks: []healthscan.PolicyPathBlock{block(path, caps...)}}}, m)
	if len(items) != 1 {
		t.Fatalf("%s: got %d items, want 1: %+v", path, len(items), items)
	}
	return items[0]
}

func requireUnmappable(t *testing.T, it Item, want UnmappableCategory) {
	t.Helper()
	if it.Outcome != Unmappable || it.Category != want || it.Reason == "" {
		t.Fatalf("%s: got outcome=%q category=%q scope=(%d,%d) perms=%v reason=%q; want Unmappable/%s with a reason (a Create here grants MORE than the Vault policy)",
			it.SourceRef, it.Outcome, it.Category, it.ProposedProjectID, it.ProposedEnvironmentID, it.ProposedPermissions, it.Reason, want)
	}
}

func requireCreate(t *testing.T, it Item, project, env int) {
	t.Helper()
	if it.Outcome != Create || it.ProposedProjectID != project || it.ProposedEnvironmentID != env {
		t.Fatalf("%s: got outcome=%q scope=(%d,%d) category=%q reason=%q; want Create at (%d,%d)",
			it.SourceRef, it.Outcome, it.ProposedProjectID, it.ProposedEnvironmentID, it.Category, it.Reason, project, env)
	}
}

// The demo's ci-payments-reader: secret/data/payments/* under --path-map secret/data=P:E was
// granted secrets.read on all of P:E, which also holds mobile-app secrets (SMT witness:
// mobile-app/firebase).
func TestScopeWidening_OverrideWiderThanPolicyPath(t *testing.T) {
	m := widenMapper(t, "secret/data=1:10")
	requireUnmappable(t, buildOne(t, m, "secret/data/payments/*", "read", "list"), wantNarrowerCategory)
	// The demo's deployer: secret/data/mobile-app/* create/update must not become secrets.write
	// on the whole environment (it could overwrite payments/db).
	requireUnmappable(t, buildOne(t, m, "secret/data/mobile-app/*", "read", "list", "create", "update"), wantNarrowerCategory)
}

// An override prefix is matched as a plain string prefix: "secret/data/pay" also catches
// "secret/data/payments/..." but that policy covers only part of what the override maps.
func TestScopeWidening_OverrideStringPrefixIsNotPathCoverage(t *testing.T) {
	m := widenMapper(t, "secret/data/pay=1:10")
	requireUnmappable(t, buildOne(t, m, "secret/data/payments/*", "read"), wantNarrowerCategory)
}

// An exact (non-glob) secret path under an override covers one secret, not the override's scope.
func TestScopeWidening_OverrideExactSecretPath(t *testing.T) {
	m := widenMapper(t, "secret/data/payments=1:10")
	requireUnmappable(t, buildOne(t, m, "secret/data/payments/db", "read"), wantNarrowerCategory)
}

// Default convention: an exact secret path used to resolve to its whole environment.
func TestScopeWidening_DefaultConventionExactSecretPath(t *testing.T) {
	m := widenMapper(t)
	requireUnmappable(t, buildOne(t, m, "secret/data/team-a/prod/db", "read", "list"), wantNarrowerCategory)
	requireUnmappable(t, buildOne(t, m, "kv1/team-b/prod/x", "read"), wantNarrowerCategory)
}

// Default convention: a glob below the environment segment covers a subtree, not the environment.
func TestScopeWidening_DefaultConventionSubtreeGlob(t *testing.T) {
	m := widenMapper(t)
	requireUnmappable(t, buildOne(t, m, "secret/data/team-a/prod/db/*", "read"), wantNarrowerCategory)
	// "team-a/prod" without a glob is one secret named "prod" under team-a/, not the environment.
	requireUnmappable(t, buildOne(t, m, "secret/data/team-a/prod", "read"), wantNarrowerCategory)
}

// Two --path-map entries routing different Vault subtrees into the same Keyorix scope: a policy
// covering one of them must not get a grant that also reads the other's secrets.
func TestScopeWidening_TwoOverridesShareOneScope(t *testing.T) {
	m := widenMapper(t, "secret/data/payments/=1:10", "secret/data/mobile-app/=1:10")
	requireUnmappable(t, buildOne(t, m, "secret/data/payments/*", "read"), wantNarrowerCategory)
}

// A KV v2 metadata/ stanza grants listing and version metadata, never secret values.
func TestScopeWidening_MetadataPathIsNotSecretsRead(t *testing.T) {
	m := widenMapper(t, "secret/metadata=1:10")
	requireUnmappable(t, buildOne(t, m, "secret/metadata/*", "list"), wantMetadataCategory)
	requireUnmappable(t, buildOne(t, widenMapper(t), "secret/metadata/team-a/prod/*", "read", "list"), wantMetadataCategory)
}

// "list" alone reveals key names only (KV v1, and KV v2 data/ paths where list does nothing).
func TestScopeWidening_ListOnlyIsNotSecretsRead(t *testing.T) {
	requireUnmappable(t, buildOne(t, widenMapper(t), "kv1/team-b/prod/*", "list"), wantMetadataCategory)
	requireUnmappable(t, buildOne(t, widenMapper(t, "secret/data=1:10"), "secret/data/*", "list"), wantMetadataCategory)
}

// Green controls: a policy path that covers exactly the resolved scope still migrates.
func TestScopeWidening_ExactCoverageStillMigrates(t *testing.T) {
	requireCreate(t, buildOne(t, widenMapper(t, "secret/data=1:10"), "secret/data/*", "read", "list"), 1, 10)
	requireCreate(t, buildOne(t, widenMapper(t, "secret/data/=1:10"), "secret/data/*", "read"), 1, 10)
	requireCreate(t, buildOne(t, widenMapper(t, "secret/data/payments=1:10"), "secret/data/payments/*", "read"), 1, 10)
	requireCreate(t, buildOne(t, widenMapper(t, "secret/data/payments/=1:10"), "secret/data/payments/*", "read"), 1, 10)
	requireCreate(t, buildOne(t, widenMapper(t), "secret/data/team-a/prod/*", "read", "list"), 1, 11)
	requireCreate(t, buildOne(t, widenMapper(t), "secret/data/team-a/*", "read"), 1, 0)
	requireCreate(t, buildOne(t, widenMapper(t), "kv1/team-b/prod/*", "read", "list"), 2, 20)
	// Two overrides into different scopes: each policy covers its own scope exactly.
	two := widenMapper(t, "secret/data/payments/=1:10", "secret/data/mobile-app/=1:11")
	requireCreate(t, buildOne(t, two, "secret/data/payments/*", "read"), 1, 10)
	requireCreate(t, buildOne(t, two, "secret/data/mobile-app/*", "read"), 1, 11)
}
