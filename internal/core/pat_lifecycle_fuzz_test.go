// pat_lifecycle_fuzz_test.go — stateful fuzz harness for the PAT create -> validate
// -> restrict -> revoke/expire lifecycle (pat.go). Before this, 34 of 38
// mutation-candidate lines in pat.go were reached by no fuzz target: only
// encodePATScopes/encodePATCIDRs (indirectly, via their DecodePATScopes/
// DecodePATCIDRs counterparts in pat_fuzz_test.go) and the pure
// PATRestriction.Allows algebra (pat_authz_metamorphic_fuzz_test.go) were fuzzed.
// ValidatePATToken itself, CreateOwnPAT, the sha256Hex-then-indexed-lookup, expiry,
// and revocation had zero fuzz coverage.
//
// This drives the real lifecycle end to end against a real sqlite-backed
// LocalStorage + KeyorixCore (mirrors newPATScopingCore, pat_scoping_e2e_test.go):
// two users, several tokens issued through the real CreateOwnPAT with varied
// scopes/CIDRs/project+environment scope, one issued already-expired, and one
// revoked via the real RevokeOwnPAT. c.now is pinned to a fixed instant for the
// whole run: authEffectiveNow's clock watermark (auth.go:528) never regresses
// within a KeyorixCore's lifetime, so rewinding c.now mid-run would not reliably
// un-expire a token once observed — fixtures are expired AT CREATION instead.
//
// The PAT format (patPrefix + base64url(32 random bytes), pat.go:71) carries no
// embedded id/secret split — unlike an id-then-secret token design, there is no
// literal "another user's id, this user's secret" shape to construct. The closest
// analogue exercised here is a byte-splice between a real issued token's prefix
// and arbitrary payload bytes (mutation kind 8 below).
package core

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// patFuzzFixture is one issued (or deliberately revoked/expired) token and the
// ground truth ValidatePATToken must return for its byte-exact plaintext.
type patFuzzFixture struct {
	label       string
	raw         string
	ownerID     uint
	restriction *PATRestriction
	revoked     bool
	expired     bool
}

// newPATFuzzWorld builds a fresh core and a fixed roster of real, issued PATs for
// one fuzz iteration. A fresh world per input (rather than shared package state)
// avoids cross-worker interference under go test -fuzz's concurrent workers,
// mirroring FuzzCoreOperationSequence's newWorld (core_sequence_fuzz_test.go).
func newPATFuzzWorld(t *testing.T) (*KeyorixCore, []patFuzzFixture) {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n init: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.PersonalAccessToken{},
		&models.SystemMetadata{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)

	fixedNow := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixedNow } // pinned + deterministic for the whole run

	c.SetBootstrapToken("fuzz-bootstrap-token")
	ctx := context.Background()
	bootRes, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "fuzz-admin", Email: "fuzz-admin@example.com",
		Password: "BootstrapPass123!", DisplayName: "Fuzz Admin",
		Token: "fuzz-bootstrap-token",
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin := bootRes.User
	second, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "fuzz-second", Email: "fuzz-second@example.com",
		DisplayName: "Fuzz Second", Password: "Correct-Horse-Battery-9!",
	})
	if err != nil {
		t.Fatalf("create second user: %v", err)
	}

	var fixtures []patFuzzFixture
	mustCreate := func(label string, userID uint, scopes []string, projScope, envScope uint, cidrs []string, expiresAt *time.Time) patFuzzFixture {
		res, err := c.CreateOwnPAT(ctx, userID, label, expiresAt, scopes, projScope, envScope, cidrs)
		if err != nil {
			t.Fatalf("create PAT %s: %v", label, err)
		}
		return patFuzzFixture{
			label:   label,
			raw:     res.PlainToken,
			ownerID: userID,
			// Deliberately NOT derived via patRestrictionFrom(res.Token): that is the
			// exact function under test on the validation side too, so a bug that
			// corrupts patRestrictionFrom (e.g. a stray cross-call cache) would corrupt
			// this "expected" value identically and the oracle would never notice.
			// Built directly from the clean, caller-supplied fixture inputs instead —
			// every input here is already normalized (no dupes/blanks/bare-IP CIDRs),
			// so no re-implementation of encodePATScopes/encodePATCIDRs' normalization
			// is needed.
			restriction: expectedRestrictionFromInputs(scopes, projScope, envScope, cidrs),
			expired:     expiresAt != nil && fixedNow.After(*expiresAt),
		}
	}

	fixtures = append(fixtures, mustCreate("admin-unrestricted", admin.ID, nil, 0, 0, nil, nil))
	fixtures = append(fixtures, mustCreate("admin-scoped", admin.ID, []string{"secrets.read"}, 0, 0, nil, nil))
	fixtures = append(fixtures, mustCreate("admin-project", admin.ID, nil, 3, 0, nil, nil))
	fixtures = append(fixtures, mustCreate("admin-cidr", admin.ID, nil, 0, 0, []string{"10.0.0.0/8"}, nil))
	fixtures = append(fixtures, mustCreate("second-scoped", second.ID, []string{"secrets.write"}, 0, 0, []string{"192.168.1.0/24"}, nil))

	past := fixedNow.Add(-24 * time.Hour)
	fixtures = append(fixtures, mustCreate("admin-expired", admin.ID, nil, 0, 0, nil, &past))

	revokedIdx := len(fixtures)
	fixtures = append(fixtures, mustCreate("admin-revoked", admin.ID, []string{"audit.read"}, 0, 0, nil, nil))
	revokedTok, err := c.storage.GetPersonalAccessTokenByHash(ctx, sha256Hex(fixtures[revokedIdx].raw))
	if err != nil {
		t.Fatalf("lookup revoked PAT: %v", err)
	}
	if _, err := c.RevokeOwnPAT(ctx, admin.ID, revokedTok.ID); err != nil {
		t.Fatalf("revoke PAT: %v", err)
	}
	fixtures[revokedIdx].revoked = true

	return c, fixtures
}

// mutatePATToken applies one of a fixed set of realistic corruption/attack shapes
// to a real issued raw token. Every variant except kind 0 (byte-exact) is expected
// to produce a string that is not byte-identical to any fixture's issued
// PlainToken — the point is to drive near-miss inputs at the
// sha256Hex-then-indexed-lookup boundary (pat.go:139) and confirm none of them
// authenticate.
func mutatePATToken(base string, kind, pos byte, payload []byte) string {
	switch kind % 9 {
	case 0: // byte-exact (also exercises the true-positive path)
		return base
	case 1: // single byte flip
		if len(base) == 0 {
			return base
		}
		b := []byte(base)
		i := int(pos) % len(b)
		b[i] ^= 0xFF
		return string(b)
	case 2: // truncation
		if len(base) == 0 {
			return base
		}
		n := int(pos) % (len(base) + 1)
		return base[:n]
	case 3: // extension
		return base + string(payload)
	case 4: // case change — defeats a case-insensitive-lookup bug if one existed
		return caseFlipASCII(base)
	case 5: // prefix corruption/swap
		if secret, ok := strings.CutPrefix(base, patPrefix); ok {
			return "kx_pat_x" + secret
		}
		return base
	case 6: // whitespace / unicode confusable wrapping
		return "​" + base + " "
	case 7: // encoding variant: same secret bytes, padded StdEncoding instead of RawURLEncoding
		if secret, ok := strings.CutPrefix(base, patPrefix); ok {
			if raw, err := base64.RawURLEncoding.DecodeString(secret); err == nil {
				return patPrefix + base64.StdEncoding.EncodeToString(raw)
			}
		}
		return base
	case 8: // cross-token splice: a prefix of base plus arbitrary payload as the tail
		if len(payload) == 0 {
			return base
		}
		i := int(pos) % (len(base) + 1)
		return base[:i] + string(payload)
	}
	return base
}

func caseFlipASCII(s string) string {
	b := []byte(s)
	for i, r := range b {
		switch {
		case r >= 'a' && r <= 'z':
			b[i] = r - 32
		case r >= 'A' && r <= 'Z':
			b[i] = r + 32
		}
	}
	return string(b)
}

// expectedRestrictionFromInputs independently reconstructs the restriction a PAT
// with these exact CreateOwnPAT inputs must resolve to — WITHOUT calling
// patRestrictionFrom or any other pat.go code, so this oracle stays a true
// independent check rather than the system testing itself against itself.
func expectedRestrictionFromInputs(scopes []string, projScope, envScope uint, cidrs []string) *PATRestriction {
	if len(scopes) == 0 && projScope == 0 && envScope == 0 && len(cidrs) == 0 {
		return nil
	}
	var sc, ci []string
	if len(scopes) > 0 {
		sc = append([]string{}, scopes...)
	}
	if len(cidrs) > 0 {
		ci = append([]string{}, cidrs...)
	}
	return &PATRestriction{Permissions: sc, ProjectID: projScope, EnvironmentID: envScope, AllowedCIDRs: ci}
}

func restrictionsEqual(a, b *PATRestriction) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.ProjectID != b.ProjectID || a.EnvironmentID != b.EnvironmentID {
		return false
	}
	if !slices.Equal(a.Permissions, b.Permissions) {
		return false
	}
	return slices.Equal(a.AllowedCIDRs, b.AllowedCIDRs)
}

func safeUserID(u *models.User) any {
	if u == nil {
		return nil
	}
	return u.ID
}

// FuzzPATValidateLifecycle drives ValidatePATToken with a fuzzer-chosen base token
// (a real issued fixture, mutated, or pure free-form input) and asserts:
//
//	(a) fail-closed identity: ValidatePATToken succeeds ONLY for a byte-exact
//	    issued, unexpired, unrevoked token, and always identifies its true owner.
//	(b) revoked/expired tokens never authenticate, even byte-exact.
//	(c) restriction binding: the restriction returned always equals the one this
//	    exact token was issued with — never another fixture's.
//	(d) bounded work: validation on adversarial-length/content input completes
//	    within fuzzutil.Guard's budget (no unbounded hashing/regex blow-up).
func FuzzPATValidateLifecycle(f *testing.F) {
	f.Add(false, "", byte(0), byte(0), byte(0), []byte{})                                // byte-exact fixture 0 -> must succeed
	f.Add(false, "", byte(1), byte(1), byte(5), []byte{})                                // single byte flip
	f.Add(false, "", byte(2), byte(2), byte(3), []byte{})                                // truncate
	f.Add(false, "", byte(3), byte(3), byte(0), []byte("extra-bytes"))                   // extension
	f.Add(false, "", byte(4), byte(4), byte(0), []byte{})                                // case flip
	f.Add(false, "", byte(1), byte(5), byte(0), []byte{})                                // prefix swap
	f.Add(false, "", byte(0), byte(6), byte(0), []byte{})                                // confusable wrap
	f.Add(false, "", byte(1), byte(7), byte(0), []byte{})                                // encoding variant
	f.Add(false, "", byte(0), byte(8), byte(4), []byte("kx_pat_ZZZZZZZZ"))               // splice
	f.Add(false, "", byte(5), byte(0), byte(0), []byte{})                                // byte-exact expired -> must fail
	f.Add(false, "", byte(6), byte(0), byte(0), []byte{})                                // byte-exact revoked -> must fail
	f.Add(true, "kx_pat_", byte(0), byte(0), byte(0), []byte{})                          // bare prefix, no secret
	f.Add(true, "not-a-pat-at-all", byte(0), byte(0), byte(0), []byte{})                 // junk, no prefix
	f.Add(true, "", byte(0), byte(0), byte(0), []byte{})                                 // empty string
	f.Add(true, strings.Repeat("kx_pat_A", 100000), byte(0), byte(0), byte(0), []byte{}) // adversarial length

	f.Fuzz(func(t *testing.T, useFree bool, freeform string, fixtureIdx, mutKind, pos byte, payload []byte) {
		c, fixtures := newPATFuzzWorld(t)
		ctx := context.Background()

		var candidate string
		var want *patFuzzFixture // non-nil only when candidate is byte-exact to a known-good fixture
		if useFree || len(fixtures) == 0 {
			candidate = freeform
		} else {
			base := fixtures[int(fixtureIdx)%len(fixtures)]
			candidate = mutatePATToken(base.raw, mutKind, pos, payload)
			if candidate == base.raw {
				fx := base
				want = &fx
			}
		}

		// (d) bounded work: hashing/lookup must not blow up on adversarial length/content.
		var user *models.User
		var roles []string
		var restriction *PATRestriction
		var patID uint
		var verr error
		fuzzutil.Guard(t.Fatalf, "ValidatePATToken", func() {
			user, roles, restriction, patID, verr = c.ValidatePATToken(ctx, candidate)
		})
		_ = roles

		if want == nil {
			// Not byte-exact to any live fixture: must never authenticate, no matter how
			// close the mutation is to a real token.
			if verr == nil {
				t.Fatalf("FAIL-CLOSED VIOLATION: mutated/free-form input authenticated: kind=%d candidate=%q owner=%v", mutKind, candidate, safeUserID(user))
			}
			if user != nil || restriction != nil || patID != 0 {
				t.Fatalf("result-shape: denied validation returned non-zero identity (user=%v restriction=%v patID=%d) for %q", user, restriction, patID, candidate)
			}
			return
		}

		// Byte-exact candidate: revoked/expired must still be rejected — (b).
		if want.revoked || want.expired {
			if verr == nil {
				t.Fatalf("REVOKED/EXPIRED AUTHENTICATED: fixture %q (revoked=%v expired=%v) validated successfully", want.label, want.revoked, want.expired)
			}
			return
		}

		// Byte-exact, live token: must succeed and identify exactly its true owner — (a).
		if verr != nil {
			t.Fatalf("fixture %q: byte-exact live token failed to validate: %v", want.label, verr)
		}
		if user == nil || user.ID != want.ownerID {
			t.Fatalf("IDENTITY VIOLATION: fixture %q owner=%d, ValidatePATToken returned %v", want.label, want.ownerID, safeUserID(user))
		}
		if patID == 0 {
			t.Fatalf("fixture %q: validated but returned patID=0", want.label)
		}

		// (c) restriction binding: must equal exactly what THIS token was issued with,
		// never another fixture's restriction.
		if !restrictionsEqual(restriction, want.restriction) {
			t.Fatalf("RESTRICTION BLEED: fixture %q got=%#v want=%#v", want.label, restriction, want.restriction)
		}
		for _, other := range fixtures {
			if other.label == want.label || other.restriction == nil || want.restriction == nil {
				continue
			}
			if restrictionsEqual(restriction, other.restriction) && !restrictionsEqual(want.restriction, other.restriction) {
				t.Fatalf("RESTRICTION BLEED: fixture %q returned fixture %q's restriction", want.label, other.label)
			}
		}
	})
}
