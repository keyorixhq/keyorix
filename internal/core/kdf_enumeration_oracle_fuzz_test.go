package core

// kdf_enumeration_oracle_fuzz_test.go — KDF1 account-enumeration-by-difference
// oracle, built on the EX1 existence-oracle idea (EX1's
// server/http/existence_cost_oracle_fuzz_test.go is NOT present in this clone, so
// this is the reimplemented minimal core-level version).
//
// # What it checks
//
// An account-enumeration timing side-channel on the login path turns on whether
// the EXPENSIVE password-hash KDF (bcrypt, ~ms) runs the SAME number of times for
// an account that exists and one that does not. Keyorix equalises this with a
// dummy-hash comparison on the not-found / locked paths (auth.go). This oracle
// makes that machine-checked with the KDF1 counter: for every account-existence
// class — known-active, locked, deactivated, suspended, reset-required, and
// guaranteed-absent — VerifyPasswordCredentials MUST spend exactly ONE KDF compare
// and ZERO KDF generates. A path that skips the compare (the classic enumeration
// bug) or spends an extra one makes KDFCompares != 1 and the oracle fires.
//
// It also measures DB round-trips per class (resguard DBMeter) and asserts the
// enumeration-relevant DB parity between the classes that SHOULD be identical
// (absent vs known-active-correct vs locked). The one DB asymmetry that exists by
// design — a wrong password against an EXISTING account writes lockout-accounting
// state (recordFailedLogin) while a nonexistent account writes nothing — is
// surfaced and asserted to be bounded, and documented as an accepted difference /
// hardening candidate in the KDF1 report (it is NOT a KDF asymmetry: bcrypt, the
// dominant cost, stays balanced).
//
// # What it does NOT verify
//
//   - Only the LOCAL bcrypt login path (VerifyPasswordCredentials). PAT / API-key
//     auth hash tokens with SHA-256, not bcrypt, and SSO delegates to the IdP, so
//     none invoke the password-hash KDF — the KDF-count signal is 0/0 there by
//     construction (no KDF enumeration surface). Password-reset / setup-consume /
//     SCIM GENERATE hashes on admin-driven write flows, not on a username lookup,
//     so they are not enumeration oracles on the read side.
//   - It does not measure wall-clock timing (deliberately: the KDF count is the
//     deterministic proxy for it) and cannot see KDF work that bypasses the shared
//     internal/kdfmeter wrapper (a direct golang.org/x/crypto/bcrypt call would be
//     invisible; the kdfmeter guard test forbids new production bypasses).
//   - "Wrong-tenant account" is N/A: Keyorix users are global (no per-tenant user
//     namespace; username has one partial-unique index), so there is no
//     wrong-tenant existence class on this path. Documented, not silently dropped.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/kdfmeter"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"golang.org/x/crypto/bcrypt"
)

// kdfEnumResetTables is the explicit table list reset between inputs. Only the
// users table is dirtied by VerifyPasswordCredentials (via recordFailedLogin), so
// that is all that must be restored; listed explicitly so a future write to
// another table cannot silently escape the reset.
var kdfEnumResetTables = []string{"users"}

// kdfEnumKnownPassword is the correct password for the seeded accounts; the hash
// is computed ONCE (kdfEnumKnownHash) at MinCost so per-input reseeding never pays
// a bcrypt generate (and so the reseed is invisible to the KDF meter).
const kdfEnumKnownPassword = "Correct#Horse9!"

var kdfEnumKnownHash string

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte(kdfEnumKnownPassword), bcrypt.MinCost)
	if err != nil {
		panic("kdf enum seed hash: " + err.Error())
	}
	kdfEnumKnownHash = string(h)
}

// kdfEnumClass is one account-existence class the oracle probes.
type kdfEnumClass struct {
	name     string
	username string // the lookup key sent to VerifyPasswordCredentials
	// correctPW true drives the account's correct password (exercises the
	// state-gate branches that only run AFTER a successful compare); false drives
	// the fuzzer's candidate password (a wrong-password attempt).
	correctPW bool
	// balancedDB true means this class must have the SAME DB round-trip count as
	// the absent baseline (no lockout write). The wrong-password-on-existing class
	// is the deliberate exception.
	balancedDB bool
}

// seedKDFEnumWorld resets w and seeds one user per existence class. folded returns
// the folded form GetUserByUsername will match on.
func seedKDFEnumWorld(t *testing.T, w *fuzzworld.World) {
	t.Helper()
	if err := w.Reset(kdfEnumResetTables); err != nil {
		t.Fatalf("reset: %v", err)
	}
	future := time.Now().Add(time.Hour)
	mk := func(id uint, uname, state string, active bool, lockedUntil *time.Time) {
		folded, ferr := identity.NewFoldedName(uname)
		if ferr != nil {
			t.Fatalf("fold %q: %v", uname, ferr)
		}
		u := &models.User{
			ID:               id,
			Username:         uname,
			UsernameFolded:   folded.Folded(),
			Email:            uname + "@x.io",
			EmailFolded:      uname + "@x.io",
			PasswordHash:     kdfEnumKnownHash,
			IsActive:         active,
			AccountState:     state,
			LoginLockedUntil: lockedUntil,
		}
		if err := w.DB.Create(u).Error; err != nil {
			t.Fatalf("seed user %q: %v", uname, err)
		}
	}
	mk(1, "alice", "active", true, nil)                     // known-active
	mk(2, "locked", "active", true, &future)                // locked
	mk(3, "deact", "active", false, nil)                    // deactivated (IsActive=false)
	mk(4, "susp", "suspended", true, nil)                   // suspended account_state
	mk(5, "resetreq", "password_reset_required", true, nil) // restricted state
}

// kdfEnumClasses returns the classes to probe for a given fuzzer candidate
// password. absentName is a fuzzer-chosen username forced to be absent.
func kdfEnumClasses(absentName string) []kdfEnumClass {
	return []kdfEnumClass{
		{name: "absent_wrong", username: absentName, correctPW: false, balancedDB: true},
		{name: "known_correct", username: "alice", correctPW: true, balancedDB: true},
		{name: "known_wrong", username: "alice", correctPW: false, balancedDB: false}, // writes lockout state — the accepted DB asymmetry
		{name: "locked", username: "locked", correctPW: false, balancedDB: true},
		{name: "deactivated_correct", username: "deact", correctPW: true, balancedDB: true},
		{name: "suspended_correct", username: "susp", correctPW: true, balancedDB: true},
		{name: "resetreq_correct", username: "resetreq", correctPW: true, balancedDB: true},
	}
}

// checkKDFParity is the oracle's core assertion, factored out so the committed
// red/green self-test (TestKDFEnumerationOracle_ParityCheckRedGreen) can drive it
// with synthetic inputs. It returns a non-nil error describing the first class
// whose KDF cost deviates from "exactly 1 compare, 0 generate".
func checkKDFParity(results map[string]resguard.Cost) error {
	for name, c := range results {
		if c.KDFGenerates != 0 || c.KDFCompares != 1 {
			return fmt.Errorf("class %q spent KDFGenerates=%d KDFCompares=%d, want 0/1: the password-hash cost is NOT balanced across account-existence classes (enumeration oracle)",
				name, c.KDFGenerates, c.KDFCompares)
		}
	}
	return nil
}

// newKDFEnumCore builds a core over the world's DB with login lockout ENABLED
// (MaxAttempts high so a single probe never actually locks within one input, but
// recordFailedLogin still runs — the path that produces the accepted DB
// asymmetry).
func newKDFEnumCore(w *fuzzworld.World) *KeyorixCore {
	c := NewKeyorixCore(store.NewLocalStorage(w.DB))
	c.SetLoginLockoutPolicy(LoginLockoutPolicy{
		Enabled:      true,
		MaxAttempts:  1000,
		Window:       time.Hour,
		BaseCooldown: time.Minute,
		MaxCooldown:  time.Hour,
	})
	return c
}

func FuzzKDFEnumerationOracle(f *testing.F) {
	SetBcryptCostForTesting(bcrypt.MinCost)

	worlds := fuzzworld.Worlds(f, "kdf1enum", ":memory:", 1)

	kdf := resguard.NewKDFMeter()
	prevObs := kdf.Install()
	f.Cleanup(func() { kdfmeter.SetObserver(prevObs) })

	type wctx struct {
		w     *fuzzworld.World
		core  *KeyorixCore
		probe *resguard.Probe
	}
	var wcs []wctx
	for _, w := range worlds {
		dbm := resguard.NewDBMeter()
		if err := dbm.Install(w.DB); err != nil {
			f.Fatalf("install dbmeter (%s): %v", w.Backend, err)
		}
		wcs = append(wcs, wctx{
			w:     w,
			core:  newKDFEnumCore(w),
			probe: resguard.New(f, resguard.Options{DB: dbm, KDF: kdf}),
		})
	}

	f.Add("guess-123", "ghost")
	f.Add("", "")
	f.Add("Correct#Horse9!", "alice-but-absent")

	f.Fuzz(func(t *testing.T, candidatePW, absentName string) {
		// Keep the absent username genuinely absent and foldable; fall back to a
		// fixed sentinel when the fuzzer input collides with a seeded name or
		// cannot be folded.
		if _, err := identity.NewFoldedName(absentName); err != nil || absentName == "" {
			absentName = "ghost-sentinel-xyz"
		}
		switch absentName {
		case "alice", "locked", "deact", "susp", "resetreq":
			absentName = "ghost-" + absentName
		}

		for _, wc := range wcs {
			seedKDFEnumWorld(t, wc.w)
			classes := kdfEnumClasses(absentName)
			results := make(map[string]resguard.Cost, len(classes))
			for _, cl := range classes {
				pw := candidatePW
				if cl.correctPW {
					pw = kdfEnumKnownPassword
				}
				cost := wc.probe.Measure(len(pw), func() {
					_, _ = wc.core.VerifyPasswordCredentials(context.Background(), cl.username, pw)
				})
				results[cl.name] = cost
			}

			// HARD: KDF parity across every class.
			if err := checkKDFParity(results); err != nil {
				t.Fatalf("[%s] KDF ENUMERATION ORACLE fired: %v (candidatePW=%q absent=%q)",
					wc.w.Backend, err, candidatePW, absentName)
			}

			// HARD: DB parity across the classes that must match the absent baseline.
			base := results["absent_wrong"].DBQueries
			for _, cl := range classes {
				if !cl.balancedDB {
					continue
				}
				if got := results[cl.name].DBQueries; got != base {
					t.Fatalf("[%s] DB ENUMERATION ORACLE fired: class %q DBQueries=%d != absent baseline %d (candidatePW=%q); a per-class DB-round-trip difference is a username-existence oracle",
						wc.w.Backend, cl.name, got, base, candidatePW)
				}
			}

			// SOFT/BOUNDED: the known, accepted asymmetry — a wrong password against
			// an existing account writes lockout-accounting state. Assert it is
			// bounded (a few extra round-trips, not unbounded) so a regression that
			// blows it up is still caught; the magnitude is documented as accepted in
			// the KDF1 report.
			delta := results["known_wrong"].DBQueries - base
			if delta < 0 || delta > 8 {
				t.Fatalf("[%s] accepted lockout-write asymmetry is out of its documented bound: known_wrong=%d absent=%d delta=%d (want 0..8)",
					wc.w.Backend, results["known_wrong"].DBQueries, base, delta)
			}
		}
	})
}

// TestKDFEnumerationOracle_ParityCheckRedGreen is the committed red/green proof
// for the oracle's assertion logic: a balanced result set passes, and a result
// set where a single class skips the KDF compare (the enumeration bug) fails. This
// is the guard-watched-fail that does not require a throwaway production edit (the
// report records a separate transient production-mutation run that confirms the
// end-to-end path).
func TestKDFEnumerationOracle_ParityCheckRedGreen(t *testing.T) {
	green := map[string]resguard.Cost{
		"absent_wrong":  {KDFCompares: 1},
		"known_correct": {KDFCompares: 1},
		"locked":        {KDFCompares: 1},
	}
	if err := checkKDFParity(green); err != nil {
		t.Fatalf("GREEN: balanced result set must pass, got: %v", err)
	}

	// RED: the not-found path forgot its dummy compare — 0 compares.
	red := map[string]resguard.Cost{
		"absent_wrong":  {KDFCompares: 0}, // the enumeration defect
		"known_correct": {KDFCompares: 1},
	}
	if err := checkKDFParity(red); err == nil {
		t.Fatal("RED: a class that skips the KDF compare must be caught, but checkKDFParity returned nil")
	}

	// RED: an extra compare (double-hash) on one class is also an oracle.
	red2 := map[string]resguard.Cost{
		"absent_wrong":  {KDFCompares: 1},
		"known_correct": {KDFCompares: 2},
	}
	if err := checkKDFParity(red2); err == nil {
		t.Fatal("RED: a class spending an extra KDF compare must be caught, but checkKDFParity returned nil")
	}
}
