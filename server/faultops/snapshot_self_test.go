package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSnapshotTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}
	return db
}

// TestSnapshotDB_IdenticalWorldsHashEqual is the green control: two DBs built by
// the same sequence of writes must produce an identical overall hash.
func TestSnapshotDB_IdenticalWorldsHashEqual(t *testing.T) {
	dbA := newSnapshotTestDB(t)
	dbB := newSnapshotTestDB(t)
	for _, db := range []*gorm.DB{dbA, dbB} {
		if err := db.Create(&models.Project{Name: "p1", Description: "d"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	sa, err := snapshotDB(dbA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := snapshotDB(dbB)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Hash != sb.Hash {
		t.Fatalf("identical worlds hashed differently: %s vs %s", sa.Hash, sb.Hash)
	}
}

// TestSnapshotDB_ExtraRowChangesHash is the red-proof for the base mechanism: a
// genuinely different world (an extra row) MUST produce a different hash, and the
// differing table must be identifiable via the per-table breakdown.
func TestSnapshotDB_ExtraRowChangesHash(t *testing.T) {
	dbA := newSnapshotTestDB(t)
	dbB := newSnapshotTestDB(t)
	if err := dbA.Create(&models.Project{Name: "p1"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbB.Create(&models.Project{Name: "p1"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbB.Create(&models.Project{Name: "p2 — extra"}).Error; err != nil {
		t.Fatal(err)
	}
	sa, err := snapshotDB(dbA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := snapshotDB(dbB)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Hash == sb.Hash {
		t.Fatalf("an extra row did not change the overall hash")
	}
	if sa.Tables["Project"].Hash == sb.Tables["Project"].Hash {
		t.Fatalf("an extra Project row did not change the Project table hash")
	}
	// Every OTHER table must still match — this snapshot only touched Project.
	for name := range sa.Tables {
		if name == "Project" {
			continue
		}
		if sa.Tables[name].Hash != sb.Tables[name].Hash {
			t.Fatalf("untouched table %s hash changed between worlds", name)
		}
	}
}

// TestSnapshotDB_ExcludedTimestampDoesNotAffectHash red-proofs the exclusion
// list: two rows differing ONLY in CreatedAt (which this harness cannot control
// — GORM stamps it internally) must hash identically, or every legitimate op
// sequence would spuriously "fail" oracle (a).
func TestSnapshotDB_ExcludedTimestampDoesNotAffectHash(t *testing.T) {
	dbA := newSnapshotTestDB(t)
	dbB := newSnapshotTestDB(t)
	pa := &models.Project{Name: "p1"}
	if err := dbA.Create(pa).Error; err != nil {
		t.Fatal(err)
	}
	// Force a different CreatedAt by writing it directly after insert — the
	// clean way to prove the hash function itself ignores it, independent of
	// however GORM would normally stamp two back-to-back inserts.
	if err := dbA.Model(&models.Project{}).Where("id = ?", pa.ID).
		UpdateColumn("created_at", pa.CreatedAt.Add(48*3600*1e9)).Error; err != nil {
		t.Fatal(err)
	}
	pb := &models.Project{Name: "p1"}
	if err := dbB.Create(pb).Error; err != nil {
		t.Fatal(err)
	}
	sa, err := snapshotDB(dbA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := snapshotDB(dbB)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Hash != sb.Hash {
		t.Fatalf("rows differing only in the excluded CreatedAt field hashed differently")
	}
}

// TestSnapshotDB_PresenceOnlyFieldTolerance red-proofs presenceOnlyFields: two
// PersonalAccessToken rows with DIFFERENT TokenHash bytes (as a real random
// token's hash always is) but otherwise identical must hash the SAME, and two
// rows where one legitimately never got a token written (empty TokenHash) vs one
// that did must hash DIFFERENTLY — proving this reduces to a presence check, not
// a no-op that ignores the field entirely.
func TestSnapshotDB_PresenceOnlyFieldTolerance(t *testing.T) {
	dbA := newSnapshotTestDB(t)
	dbB := newSnapshotTestDB(t)
	u := &models.User{Username: "u1", Email: "u1@example.com"}
	if err := dbA.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	u2 := &models.User{Username: "u1", Email: "u1@example.com"}
	if err := dbB.Create(u2).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbA.Create(&models.PersonalAccessToken{UserID: u.ID, Name: "t1", TokenHash: "aaaa...random-hash-one"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbB.Create(&models.PersonalAccessToken{UserID: u2.ID, Name: "t1", TokenHash: "bbbb...totally-different-random-hash"}).Error; err != nil {
		t.Fatal(err)
	}
	sa, err := snapshotDB(dbA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := snapshotDB(dbB)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Tables["PersonalAccessToken"].Hash != sb.Tables["PersonalAccessToken"].Hash {
		t.Fatalf("two tokens differing only in TokenHash bytes hashed differently — presence-only redaction did not apply")
	}

	// Now prove it's a real presence check, not a full skip: an EMPTY TokenHash
	// (the token was never actually written — the bug this harness hunts for)
	// must still be distinguishable from a non-empty one.
	dbC := newSnapshotTestDB(t)
	u3 := &models.User{Username: "u1", Email: "u1@example.com"}
	if err := dbC.Create(u3).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbC.Create(&models.PersonalAccessToken{UserID: u3.ID, Name: "t1", TokenHash: ""}).Error; err != nil {
		t.Fatal(err)
	}
	sc, err := snapshotDB(dbC)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Tables["PersonalAccessToken"].Hash == sc.Tables["PersonalAccessToken"].Hash {
		t.Fatalf("a row with an EMPTY TokenHash hashed the same as one with a real token — presence check is not distinguishing written-vs-not")
	}
}

// TestSnapshotDB_LastUsedStepPresenceOnlyTolerance red-proofs the
// MFASecret.LastUsedStep presenceOnlyFields entry: two rows with DIFFERENT
// step numbers (as two real TOTP verifications separated by real elapsed
// time always produce, since the step is wall-clock derived) must hash the
// SAME, and a row that never had a code accepted (nil) vs one that did must
// still hash DIFFERENTLY — same shape as TestSnapshotDB_PresenceOnlyFieldTolerance
// above, proving this reduces to a presence check, not a full skip of the
// field. Found live: TestWorldReuseSoundness flagged "MFASecret.LastUsedStep
// differs (N vs N-1)" between two passes of the same logical state taken
// seconds apart (PR #2392's rebase, fuzz/mfa-reauth-ops).
func TestSnapshotDB_LastUsedStepPresenceOnlyTolerance(t *testing.T) {
	dbA := newSnapshotTestDB(t)
	dbB := newSnapshotTestDB(t)
	u := &models.User{Username: "u1", Email: "u1@example.com"}
	if err := dbA.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	u2 := &models.User{Username: "u1", Email: "u1@example.com"}
	if err := dbB.Create(u2).Error; err != nil {
		t.Fatal(err)
	}
	stepA := int64(59700695)
	stepB := int64(59700696)
	if err := dbA.Create(&models.MFASecret{UserID: u.ID, Activated: true, LastUsedStep: &stepA}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbB.Create(&models.MFASecret{UserID: u2.ID, Activated: true, LastUsedStep: &stepB}).Error; err != nil {
		t.Fatal(err)
	}
	sa, err := snapshotDB(dbA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := snapshotDB(dbB)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Tables["MFASecret"].Hash != sb.Tables["MFASecret"].Hash {
		t.Fatalf("two MFASecret rows differing only in LastUsedStep (%d vs %d, as two real verifications seconds apart "+
			"always do) hashed differently — presence-only redaction did not apply", stepA, stepB)
	}

	// Now prove it's a real presence check, not a full skip: a NIL LastUsedStep
	// (no code ever accepted — the state this field exists to distinguish) must
	// still be distinguishable from a non-nil one.
	dbC := newSnapshotTestDB(t)
	u3 := &models.User{Username: "u1", Email: "u1@example.com"}
	if err := dbC.Create(u3).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbC.Create(&models.MFASecret{UserID: u3.ID, Activated: true, LastUsedStep: nil}).Error; err != nil {
		t.Fatal(err)
	}
	sc, err := snapshotDB(dbC)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Tables["MFASecret"].Hash == sc.Tables["MFASecret"].Hash {
		t.Fatalf("a row with a NIL LastUsedStep hashed the same as one with a step recorded — presence check is not distinguishing accepted-vs-never")
	}
}

// TestCanonicalRow_BreakGlassAndAccessReviewRoleNameStillCompared red-proofs
// typeScopedPresenceOnlyFields: RoleName is presence-only ONLY on
// DynamicSecretLease (where it's a random per-call login name) -- on every
// OTHER model that happens to share the field name, it must still be
// byte-compared. A changed BreakGlassActivation.RoleName (which role an
// emergency break-glass activation granted) or AccessReviewItem.RoleName (a
// role-name snapshot in an access-review campaign entry) must still change
// that table's hash; a changed DynamicSecretLease.RoleName/LeaseID must NOT.
// Without the type scoping, a bare global presenceOnlyFields["RoleName"]
// entry would silently blind the oracle to the first two cases -- this test
// fails against that shape (confirmed by temporarily reverting
// typeScopedPresenceOnlyFields to a global presenceOnlyFields entry and
// rerunning: BreakGlassActivation/AccessReviewItem's assertions below go red).
func TestCanonicalRow_BreakGlassAndAccessReviewRoleNameStillCompared(t *testing.T) {
	dbA := newSnapshotTestDB(t)
	dbB := newSnapshotTestDB(t)

	if err := dbA.Create(&models.BreakGlassActivation{ProjectID: 1, UserID: 1, RoleID: 1, RoleName: "system_admin", State: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbB.Create(&models.BreakGlassActivation{ProjectID: 1, UserID: 1, RoleID: 1, RoleName: "viewer", State: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	sa, err := snapshotDB(dbA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := snapshotDB(dbB)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Tables["BreakGlassActivation"].Hash == sb.Tables["BreakGlassActivation"].Hash {
		t.Fatalf("two BreakGlassActivation rows differing only in RoleName (%q vs %q) hashed the same -- "+
			"a corrupted/wrong-role break-glass record would go undetected", "system_admin", "viewer")
	}

	dbC := newSnapshotTestDB(t)
	dbD := newSnapshotTestDB(t)
	if err := dbC.Create(&models.AccessReviewItem{CampaignID: 1, PrincipalType: "user", PrincipalID: 1, RoleName: "system_admin"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbD.Create(&models.AccessReviewItem{CampaignID: 1, PrincipalType: "user", PrincipalID: 1, RoleName: "viewer"}).Error; err != nil {
		t.Fatal(err)
	}
	sc, err := snapshotDB(dbC)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := snapshotDB(dbD)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Tables["AccessReviewItem"].Hash == sd.Tables["AccessReviewItem"].Hash {
		t.Fatalf("two AccessReviewItem rows differing only in RoleName (%q vs %q) hashed the same -- "+
			"a corrupted access-review snapshot would go undetected", "system_admin", "viewer")
	}

	// Positive control, same shape as TestSnapshotDB_PresenceOnlyFieldTolerance
	// above: DynamicSecretLease.RoleName/LeaseID differences (genuinely random
	// per issue) must still be tolerated -- the type scoping narrows the
	// exemption, it must not have accidentally removed it.
	dbE := newSnapshotTestDB(t)
	dbF := newSnapshotTestDB(t)
	if err := dbE.Create(&models.DynamicSecretLease{ConfigID: 1, LeaseID: "lease-aaaa", RoleName: "kx_dyn_aaaa", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbF.Create(&models.DynamicSecretLease{ConfigID: 1, LeaseID: "lease-bbbb", RoleName: "kx_dyn_bbbb", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	se, err := snapshotDB(dbE)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := snapshotDB(dbF)
	if err != nil {
		t.Fatal(err)
	}
	if se.Tables["DynamicSecretLease"].Hash != sf.Tables["DynamicSecretLease"].Hash {
		t.Fatalf("two DynamicSecretLease rows differing only in LeaseID/RoleName (both genuinely random per issue) hashed differently -- the type-scoped exemption regressed")
	}
}
