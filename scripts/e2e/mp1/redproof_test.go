//go:build e2e

package mp1

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// This file is the RED-PROOF suite required by the repo's "a guard nobody has
// watched fail is not a guard" rule. Each oracle's decision logic is exercised
// here against a PLANTED violation (must go red) AND a known-good input (must
// stay green). Because production code must not be changed, the planted
// violation lives in the test input, not in Keyorix: these proofs validate
// that the CHECK fires on the shape it claims to catch — they do NOT, and are
// not claimed to, prove that Keyorix ever produces that shape. (See
// CLAUDE.md's "validate a mechanism against a failure that actually
// happened" caveat.)

// TestRedProof_SerialEquivalence: the serial-equivalence check must flag a
// final value that no successful write produced (red), and accept one that a
// successful write produced (green).
func TestRedProof_SerialEquivalence(t *testing.T) {
	success := map[string]struct{}{"v0": {}, "v1": {}, "v2": {}}

	// GREEN: a surviving value that a successful write set.
	if serialEquivViolation("v2", success) {
		t.Fatal("green case misfired: v2 WAS set by a successful write but was flagged a violation")
	}
	// RED: a phantom/torn value no successful write set.
	if !serialEquivViolation("v-PHANTOM", success) {
		t.Fatal("RED PROOF FAILED: a final value set by no successful write was NOT flagged — the serial-equivalence oracle is vacuous")
	}
	t.Log("serial-equivalence oracle: red on a phantom value, green on a real successful value")
}

// TestRedProof_Convergence: the convergence check must flag replicas that
// disagree (red) and accept replicas that agree (green).
func TestRedProof_Convergence(t *testing.T) {
	if !allEqual([]string{"x", "x", "x"}) {
		t.Fatal("green case misfired: identical reads flagged as divergent")
	}
	if allEqual([]string{"x", "x", "y"}) {
		t.Fatal("RED PROOF FAILED: divergent cross-replica reads were treated as converged — the convergence oracle is vacuous")
	}
	t.Log("convergence oracle: red when one replica disagrees, green when all agree")
}

// TestRedProof_Canary: the log-scan check must flag a log containing a secret
// value (red) and pass a clean log (green).
func TestRedProof_Canary(t *testing.T) {
	values := []string{"CANARY-super-secret-value", "another-secret-9d2f"}

	clean := "2026-11-14 INFO served GET /api/v1/secrets/42 200 in 3ms user=mp1admin"
	if hits := scanLogForSecrets(clean, values, 6); len(hits) != 0 {
		t.Fatalf("green case misfired: clean log flagged hits %v", hits)
	}

	leaked := clean + "\nDEBUG decrypted value=CANARY-super-secret-value for secret 42"
	hits := scanLogForSecrets(leaked, values, 6)
	if len(hits) == 0 {
		t.Fatal("RED PROOF FAILED: a log line containing a secret value produced NO canary hit — the canary oracle is vacuous")
	}
	t.Logf("canary oracle: red on a leaking log (hit %v), green on a clean log", hits)
}

// TestRedProof_AuditCount: the per-op audit-count check must flag a dropped
// (0) or duplicated (>=2) audit row and accept exactly one.
func TestRedProof_AuditCount(t *testing.T) {
	if bad, _ := auditCountViolation(map[int]int{1: 1, 2: 1, 3: 1}); bad {
		t.Fatal("green case misfired: exactly-one-per-op was flagged a violation")
	}
	if bad, _ := auditCountViolation(map[int]int{1: 1, 2: 2, 3: 1}); !bad {
		t.Fatal("RED PROOF FAILED: a duplicated audit row (count 2) was NOT flagged — the audit-count oracle would miss a double-write")
	}
	if bad, _ := auditCountViolation(map[int]int{1: 1, 2: 0, 3: 1}); !bad {
		t.Fatal("RED PROOF FAILED: a dropped audit row (count 0) was NOT flagged — the audit-count oracle would miss a lost append")
	}
	t.Log("audit-count oracle: red on a duplicated or dropped row, green on exactly one per op")
}

// TestRedProof_Uniqueness: the uniqueness check must flag a run with two
// winners or a disagreeing row count (red) and accept exactly-one/exactly-one
// (green).
func TestRedProof_Uniqueness(t *testing.T) {
	if bad, _ := uniquenessViolation(1, 1); bad {
		t.Fatal("green case misfired: exactly one winner + one row was flagged a violation")
	}
	if bad, _ := uniquenessViolation(2, 2); !bad {
		t.Fatal("RED PROOF FAILED: two winners + two rows was NOT flagged — the uniqueness oracle is vacuous")
	}
	if bad, _ := uniquenessViolation(1, 2); !bad {
		t.Fatal("RED PROOF FAILED: one ack but two surviving rows was NOT flagged — the uniqueness oracle misses a split-brain insert")
	}
	if bad, _ := uniquenessViolation(0, 0); !bad {
		t.Fatal("RED PROOF FAILED: zero winners was NOT flagged — a total-failure run would pass silently")
	}
	t.Log("uniqueness oracle: red on two-winners / ack-row mismatch / zero-winners, green on exactly-one")
}

// TestRedProof_UniquenessLive is a LIVE red proof: it confirms the DB unique
// constraint the oracle leans on is actually enforced, by creating a name and
// then creating the SAME name again (sequentially, on a different replica). The
// second create MUST be rejected and the active-row count MUST stay 1. If a
// second create succeeded, the uniqueness oracle would (correctly) fire — this
// proves its "exactly one" demand is meaningful against the real schema, not
// vacuous. PG-gated.
func TestRedProof_UniquenessLive(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	name := fmt.Sprintf("mp1-uniqlive-%d", time.Now().UnixNano())
	st1, err := c.createProject(c.Replica(0), name)
	if err != nil || (st1 != http.StatusCreated && st1 != http.StatusOK) {
		t.Fatalf("first create should succeed: status=%d err=%v", st1, err)
	}
	st2, err := c.createProject(c.Replica(1%len(c.Replicas)), name)
	if err != nil {
		t.Fatalf("second create transport error: %v", err)
	}
	if st2 == http.StatusCreated || st2 == http.StatusOK {
		t.Fatalf("RED PROOF FAILED: a duplicate project name was accepted (HTTP %d) on a second replica — the unique constraint the oracle relies on is NOT enforced", st2)
	}
	if rows := c.countActiveProjects(t, name); rows != 1 {
		t.Fatalf("RED PROOF FAILED: after a duplicate create attempt there are %d active rows, want 1", rows)
	}
	t.Logf("uniqueness constraint live: duplicate rejected (HTTP %d), still exactly one active row", st2)
}

// TestRedProof_RevokedPATLive is a LIVE red proof against the real cluster: it
// confirms the revoke-visibility oracle is not vacuous by showing the opposite
// of a revoke — a PAT that is NEVER revoked stays accepted across the full
// window on every replica. The TestRevokedPATDenied oracle demands an eventual
// 401; this proves that demand is meaningful, because without a revoke the 401
// never comes (so the oracle would, correctly, go red). PG-gated.
func TestRedProof_RevokedPATLive(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)
	n := len(c.Replicas)

	rawToken, _ := c.createPAT(t, c.Replica(0), "mp1-neverrevoke-"+fmt.Sprint(time.Now().UnixNano()))

	// NOTE: deliberately NOT revoked. Across a full validTokenTTL window the
	// token must stay accepted on every replica; if it ever flips to 401 here
	// the revoke oracle's premise (a 401 means the revoke took effect) would
	// be unsound.
	deadline := time.Now().Add(validTokenTTL + 2*time.Second)
	for time.Now().Before(deadline) {
		for i := range n {
			if st := c.authProbe(c.Replica(i), rawToken); st == http.StatusUnauthorized {
				t.Fatalf("a never-revoked PAT was denied (401) on replica %d — the revoke oracle's 401 signal is not attributable to the revoke", i)
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Logf("never-revoked PAT stayed accepted on all %d replicas across %s — the revoke oracle's 401 is attributable to the revoke", n, validTokenTTL)
}
