package store_test

// Known findings from FuzzStorageBackendDifferentialV2. Each test PINS a divergence that
// was minimised, replayed three times and classified (docs/fuzzing/pg-sqlite-differential.md).
// The fuzz target gates the specific input class so a campaign can keep looking for other
// divergences. When a finding is fixed its test fails with "FIXED": delete the gate in the
// fuzz target and the test together.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// F-1: ListSecrets{Search} lowercases both sides with LOWER(). SQLite's built-in LOWER
// folds ASCII only; PostgreSQL's follows the database locale. A secret named "ÄÖ" is
// found by searching "äö" on PostgreSQL and missed on SQLite. Keyorix bug (the comment on
// SecretFilter.Search promises case-insensitive matching on both backends); functional,
// not security-relevant.
func TestBackendDifferentialKnownFinding_F1_SearchUnicodeCase(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
	ctx := context.Background()
	got := map[string]int64{}
	for _, s := range []*diffSide{w.s, w.p} {
		if _, err := s.ls.CreateSecret(ctx, &models.SecretNode{Name: "ÄÖ", ProjectID: s.proj, EnvironmentID: s.env, OwnerID: diffFixedOwnerID, IsSecret: true}); err != nil {
			t.Fatalf("%s CreateSecret: %v", s.label, err)
		}
		q := "äö"
		_, total, err := s.ls.ListSecrets(ctx, &storage.SecretFilter{ProjectID: &s.proj, Search: &q, PageSize: 10})
		if err != nil {
			t.Fatalf("%s ListSecrets: %v", s.label, err)
		}
		got[s.label] = total
	}
	if got["sqlite"] == got["postgres"] {
		t.Fatalf("FIXED: F-1 no longer diverges (sqlite=%d postgres=%d); remove the gated:F-1 branch in diffListSecrets and this test", got["sqlite"], got["postgres"])
	}
	t.Logf("F-1 still reproduces: sqlite found %d, postgres found %d", got["sqlite"], got["postgres"])
}

// F-2 / F-3: ListUsers{Username} and ListUsers{Email} use plain `LIKE '%x%'`. SQLite's
// LIKE is ASCII-case-insensitive, PostgreSQL's is case-sensitive (ILIKE exists for that),
// so filtering for "alpha" returns the user "Alpha" on SQLite only. The free-text
// Search filter already switches to ILIKE on PostgreSQL for exactly this reason; the two
// field filters were missed. Keyorix bug, functional; not security-relevant (admin user
// listing filters).
func TestBackendDifferentialKnownFinding_F2F3_UserFieldFilterCase(t *testing.T) {
	w := newDiffWorld(t, "diffv2known_")
	w.reset(t)
	ctx := context.Background()
	for _, tc := range []struct{ id, field string }{{"F-2", "username"}, {"F-3", "email"}} {
		got := map[string]int64{}
		for _, s := range []*diffSide{w.s, w.p} {
			if err := diffWipeTables2(s); err != nil {
				t.Fatal(err)
			}
			u := &models.User{Username: "Alpha", UsernameFolded: "alpha", Email: "Alpha@x.io", EmailFolded: "alpha@x.io", IsActive: true}
			if _, err := s.ls.CreateUser(ctx, u); err != nil {
				t.Fatalf("%s CreateUser: %v", s.label, err)
			}
			fl := &storage.UserFilter{Page: 1, PageSize: 10}
			if tc.field == "username" {
				fl.Username = ptrOf("alpha")
			} else {
				fl.Email = ptrOf("alpha@x.io")
			}
			_, total, err := s.ls.ListUsers(ctx, fl)
			if err != nil {
				t.Fatalf("%s ListUsers: %v", s.label, err)
			}
			got[s.label] = total
		}
		if got["sqlite"] == got["postgres"] {
			t.Fatalf("FIXED: %s no longer diverges (sqlite=%d postgres=%d); remove the exactOnly gate for this variant in diffListUsers and this test", tc.id, got["sqlite"], got["postgres"])
		}
		t.Logf("%s still reproduces: sqlite matched %d, postgres matched %d", tc.id, got["sqlite"], got["postgres"])
	}
}

func diffWipeTables2(s *diffSide) error { return diffWipeTables(s.db) }
