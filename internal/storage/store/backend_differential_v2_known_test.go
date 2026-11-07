package store_test

// Known divergences from FuzzStorageBackendDifferentialV2. Each test PINS a divergence that
// was minimised, replayed three times and classified (docs/fuzzing/pg-sqlite-differential.md).
// The fuzz target gates or normalises exactly that input class so a campaign can keep
// looking for other divergences. When one is fixed its test fails with "FIXED": delete the
// gate in the fuzz target and the test together.
//
// F-1 (ListSecrets search), F-2 and F-3 (ListUsers Username/Email filters) were pinned here
// first and are fixed by #4019; their gates and tests are gone.

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
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

// B: project-name uniqueness and lookup. The partial unique index on LOWER(name)
// (uniq_projects_name_active, #385) uses SQLite's built-in LOWER, which folds ASCII only, so
// two projects whose names differ only by NON-ASCII case ("ÄÖ" / "äö") coexist on SQLite;
// PostgreSQL rejects the second with ErrDuplicateProjectName. GetProjectByName and
// UpdateProjectFields (rename) behave the same way. #4019 deliberately left this index
// alone. Keyorix bug (storage-level uniqueness differs by backend); fix needs a folded
// project-name column or a Unicode-aware index expression plus a migration for existing
// SQLite databases that may already hold such a pair.
func TestBackendDifferentialKnownFinding_B_ProjectNameUnicodeCaseUniqueness(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
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

// C: list queries paginate without ORDER BY. On PostgreSQL the row order is whatever the
// plan yields, and the first statistics (autovacuum ANALYZE) flip the plan from the unique
// index's order to heap order. A client paging through the list while that happens sees rows
// twice and misses others. SQLite never changed order in the same scenario. Keyorix bug
// (list pagination needs a deterministic ORDER BY with an id tiebreak). The 14 campaign
// crashers did not replay (the flip needs the statistics to change mid-walk); this test
// forces the flip deterministically with an explicit ANALYZE between pages.
func TestBackendDifferentialKnownFinding_C_UnorderedPagingPlanFlip(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
	ctx := context.Background()
	s := w.p
	names := []string{"a_b", "0", "a%b", "a\\b"}
	for _, n := range names {
		fn, _ := identity.NewFoldedName(n)
		e := n + "@x.io"
		if _, err := s.ls.CreateUser(ctx, &models.User{Username: n, UsernameFolded: fn.Folded(), Email: e, EmailFolded: e, IsActive: true}); err != nil {
			t.Fatalf("CreateUser(%q): %v", n, err)
		}
	}
	var walk []string
	for page := 1; page <= len(names); page++ {
		if page == 2 {
			if err := s.db.Exec("ANALYZE users").Error; err != nil { // what autovacuum does at an arbitrary moment
				t.Fatal(err)
			}
		}
		rows, _, err := s.ls.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			walk = append(walk, r.Username)
		}
	}
	seen := map[string]int{}
	for _, n := range walk {
		seen[n]++
	}
	dup := false
	for _, c := range seen {
		dup = dup || c > 1
	}
	if !dup && len(seen) == len(names) {
		t.Fatalf("FIXED: C no longer duplicates/skips across a statistics change (walk=%q); remove gate C (diffStabilisePlans) and this test", strings.Join(walk, ","))
	}
	t.Logf("C still reproduces: 4 users, 1 per page, ANALYZE between page 1 and 2: walk=%q (distinct=%d of %d)", strings.Join(walk, ","), len(seen), len(names))
}

// D: ListUsers{Search} is `LIKE` on SQLite and `ILIKE` on PostgreSQL, so a non-ASCII case
// variant ("ÄÖ" for user "äö") matches on PostgreSQL only. Same family as the #4019 fixes;
// #4019 names it as a follow-up. Keyorix bug, low (admin user search).
func TestBackendDifferentialKnownFinding_D_UserSearchUnicodeCase(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
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
