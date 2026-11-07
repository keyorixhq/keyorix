package store_test

// Known divergences from FuzzStorageBackendDifferentialV2. Each test PINS a divergence that
// was minimised, replayed three times and classified (docs/fuzzing/pg-sqlite-differential.md).
// The fuzz target gates or normalises exactly that input class so a campaign can keep
// looking for other divergences. When one is fixed its test fails with "FIXED": whichever
// lands second, the fix or this harness, deletes the gate in the fuzz target and the test
// together in the same PR.
//
// F-1 (ListSecrets search), F-2 and F-3 (ListUsers Username/Email filters) were pinned here
// first and are fixed by #4019; their gates and tests are gone. Class C is not pinned here:
// its fix (#4022) merges before this harness and carries its own PostgreSQL regression test.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A: an empty secret value reads back as nil on SQLite and as []byte{} on PostgreSQL.
// Backend-inherent (driver NULL/empty-blob mapping); no caller distinguishes them and real
// values are ciphertext. Handled by harness normalisation 7, not a code fix.
func TestBackendDifferentialKnownDifference_A_EmptyValueNilness(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
	ctx := context.Background()
	isNil := map[string]bool{}
	for _, s := range []*diffSide{w.s, w.p} {
		n, err := s.ls.CreateSecret(ctx, &models.SecretNode{Name: "a", ProjectID: s.proj, EnvironmentID: s.env, OwnerID: diffFixedOwnerID, IsSecret: true})
		if err != nil {
			t.Fatalf("%s CreateSecret: %v", s.label, err)
		}
		if _, err := s.ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: n.ID, VersionNumber: 1, EncryptedValue: []byte{}}); err != nil {
			t.Fatalf("%s CreateSecretVersion: %v", s.label, err)
		}
		v, err := s.ls.GetLatestSecretVersion(ctx, n.ID)
		if err != nil {
			t.Fatalf("%s GetLatestSecretVersion: %v", s.label, err)
		}
		isNil[s.label] = v.EncryptedValue == nil
	}
	if isNil["sqlite"] == isNil["postgres"] {
		t.Fatalf("FIXED: A no longer differs (sqlite nil=%v postgres nil=%v); drop normalisation 7 in diffVersionFP and this test", isNil["sqlite"], isNil["postgres"])
	}
	t.Logf("A still differs: empty value reads back nil on sqlite=%v, on postgres=%v", isNil["sqlite"], isNil["postgres"])
}

// diffRequireUnicodeLower skips a pin whose divergence only exists when PostgreSQL's
// LOWER() folds non-ASCII letters, which depends on the database collation (en_US.UTF-8
// does, C/POSIX does not). On a C-collation database B and D cannot be observed, and the
// pin would otherwise report a false "FIXED". It checks the behaviour itself, not the
// collation name, so any provider that folds counts.
func diffRequireUnicodeLower(t *testing.T, s *diffSide) {
	t.Helper()
	var folds bool
	if err := s.db.Raw("SELECT LOWER('ÄÖ') = 'äö'").Scan(&folds).Error; err != nil {
		t.Fatalf("probe LOWER() on %s: %v", s.label, err)
	}
	if !folds {
		var coll string
		_ = s.db.Raw("SELECT datcollate FROM pg_database WHERE datname = current_database()").Scan(&coll).Error
		t.Skipf("PostgreSQL LOWER() does not fold non-ASCII on this database (datcollate=%q): the divergence cannot be observed here, so a pass would be a false FIXED", coll)
	}
}

// B: project-name uniqueness and lookup. The partial unique index on LOWER(name)
// (uniq_projects_name_active, #385) uses SQLite's built-in LOWER, which folds ASCII only, so
// two projects whose names differ only by NON-ASCII case ("ÄÖ" / "äö") coexist on SQLite;
// PostgreSQL rejects the second with ErrDuplicateProjectName. GetProjectByName and
// UpdateProjectFields (rename) behave the same way. #4019 deliberately left this index
// alone. Storage-layer divergence, not reachable through a live writer: every project
// name write goes through internal/core's validateProjectName, which accepts ASCII
// letters, digits, space, '-' and '_' only (see the doc's class B row for the trace).
// Defence in depth; #4027 makes the index identical on both backends.
func TestBackendDifferentialKnownFinding_B_ProjectNameUnicodeCaseUniqueness(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
	diffRequireUnicodeLower(t, w.p)
	ctx := context.Background()
	second := map[string]string{}
	for _, s := range []*diffSide{w.s, w.p} {
		if _, err := s.ls.CreateProject(ctx, &models.Project{Name: "ÄÖ"}); err != nil {
			t.Fatalf("%s first CreateProject: %v", s.label, err)
		}
		_, err := s.ls.CreateProject(ctx, &models.Project{Name: "äö"})
		second[s.label] = diffClass(err)
	}
	if second["sqlite"] == second["postgres"] {
		t.Fatalf("FIXED: B no longer differs (sqlite=%s postgres=%s); remove gate B in the fuzz target and this test", second["sqlite"], second["postgres"])
	}
	t.Logf("B still differs: second project differing only by non-ASCII case: sqlite=%s postgres=%s", second["sqlite"], second["postgres"])
}

// D: ListUsers{Search} is `LIKE` on SQLite and `ILIKE` on PostgreSQL, so a non-ASCII case
// variant ("ÄÖ" for user "äö") matches on PostgreSQL only. Same family as the #4019 fixes;
// #4019 names it as a follow-up. Reachable: display_name (and an IdP-provisioned email)
// accepts any Unicode and the admin user search (users.read) passes the term straight
// through; usernames are ASCII-only. Keyorix bug, low (search results differ by backend;
// no authorization decision uses Search). Trace in the doc's class D section.
func TestBackendDifferentialKnownFinding_D_UserSearchUnicodeCase(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
	diffRequireUnicodeLower(t, w.p)
	ctx := context.Background()
	got := map[string]int64{}
	for _, s := range []*diffSide{w.s, w.p} {
		u := &models.User{Username: "äö", UsernameFolded: "äö", Email: "x@x.io", EmailFolded: "x@x.io", IsActive: true}
		if _, err := s.ls.CreateUser(ctx, u); err != nil {
			t.Fatalf("%s CreateUser: %v", s.label, err)
		}
		_, total, err := s.ls.ListUsers(ctx, &storage.UserFilter{Search: ptrOf("ÄÖ"), Page: 1, PageSize: 10})
		if err != nil {
			t.Fatalf("%s ListUsers: %v", s.label, err)
		}
		got[s.label] = total
	}
	if got["sqlite"] == got["postgres"] {
		t.Fatalf("FIXED: D no longer diverges (sqlite=%d postgres=%d); remove gate D in diffListUsers and this test", got["sqlite"], got["postgres"])
	}
	t.Logf("D still reproduces: sqlite found %d, postgres found %d", got["sqlite"], got["postgres"])
}
