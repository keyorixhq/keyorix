package store_test

// Known divergences from FuzzStorageBackendDifferentialV2. Each test PINS a divergence that
// was minimised, replayed three times and classified (docs/fuzzing/pg-sqlite-differential.md).
// The fuzz target gates or normalises exactly that input class so a campaign can keep
// looking for other divergences. When one is fixed its test fails with "FIXED": whichever
// lands second, the fix or this harness, deletes the gate in the fuzz target and the test
// together in the same PR.
//
// F-1 (ListSecrets search), F-2 and F-3 (ListUsers Username/Email filters) were pinned here
// first and are fixed by #4019; their gates and tests are gone. B (project-name uniqueness
// and lookup on non-ASCII case) is fixed by #4027 (projects.name_folded); its gate and test
// are gone too. D (ListUsers Search) is fixed by #4023, which removed its gate and test; its
// regression tests are TestListUsers_SearchUnicodeCase_{SQLite,Postgres}. Class C is not pinned here:
// its fix (#4022) merges before this harness and carries its own PostgreSQL regression test.

import (
	"context"
	"testing"

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
