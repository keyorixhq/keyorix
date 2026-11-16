//go:build e2e

package mp1

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
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

// TestRedProof_IncrementalScan: the incremental log scan (scanNewLogOutput,
// used per fuzz iteration, in TestZZ and in TestMain) must report a recorded
// value or key bytes in any log of the cluster, including output appended
// after an earlier clean pass, a value written across two passes, a renamed
// pre-restart log, and an unreadable log (red), and pass clean logs (green).
// It uses planted temp logs, not a live cluster.
func TestRedProof_IncrementalScan(t *testing.T) {
	set := newCanarySet([]string{"CANARY-post-run-value-7f3a", "fuzz-written-value-55c1"}, canaryMinLen)
	appendLog := func(path, text string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test temp path
		if err != nil {
			t.Fatalf("open planted log: %v", err)
		}
		defer f.Close() //nolint:errcheck
		if _, err := f.WriteString(text); err != nil {
			t.Fatalf("write planted log: %v", err)
		}
	}
	newCluster := func() *Cluster {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
			t.Fatalf("mkdir keys: %v", err)
		}
		appendLog(filepath.Join(dir, "keys", "dek.key"), "planted-dek-bytes-0123456789abcdef")
		c := &Cluster{}
		for i := range 2 {
			s := &harness.Server{Dir: dir, LogPath: filepath.Join(dir, fmt.Sprintf("server-%d.log", i))}
			appendLog(s.LogPath, "INFO served GET /api/v1/secrets/42 200\n")
			c.Replicas = append(c.Replicas, s)
		}
		return c
	}
	scan := func(c *Cluster) []string {
		t.Helper()
		p, _ := c.scanNewLogOutput(set)
		return p
	}

	// GREEN: clean logs, scanned twice (the second pass reads only the overlap).
	c := newCluster()
	if p, logs := c.scanNewLogOutput(set); len(p) != 0 || logs != 2 {
		t.Fatalf("green case misfired: clean logs gave problems=%v logs=%d (want none, 2)", p, logs)
	}
	if p := scan(c); len(p) != 0 {
		t.Fatalf("green case misfired: a clean re-scan gave %v", p)
	}

	// RED: a value appended after a clean pass is reported once, not again.
	appendLog(c.Replicas[1].LogPath, "DEBUG value=fuzz-written-value-55c1\n")
	if p := scan(c); len(p) != 1 {
		t.Fatalf("RED PROOF FAILED: a value appended after a clean pass gave problems=%v, want exactly 1", p)
	}
	if p := scan(c); len(p) != 0 {
		t.Fatalf("a hit was reported twice: %v", p)
	}

	// RED: a value whose bytes land in two passes is still seen (overlap).
	c = newCluster()
	appendLog(c.Replicas[0].LogPath, "DEBUG value=CANARY-post-run")
	if p := scan(c); len(p) != 0 {
		t.Fatalf("half a value was reported: %v", p)
	}
	appendLog(c.Replicas[0].LogPath, "-value-7f3a\n")
	if p := scan(c); len(p) != 1 {
		t.Fatalf("RED PROOF FAILED: a value written across two passes gave problems=%v, want exactly 1", p)
	}

	// RED: a renamed pre-restart log keeps being scanned (the SIGKILL
	// cluster's shape: the restart would otherwise truncate it).
	c = newCluster()
	_ = scan(c)
	pre := c.Replicas[1].LogPath + ".pre-restart"
	if err := os.Rename(c.Replicas[1].LogPath, pre); err != nil {
		t.Fatalf("rename: %v", err)
	}
	c.moveLog(c.Replicas[1].LogPath, pre)
	appendLog(c.Replicas[1].LogPath, "INFO restarted\n")
	appendLog(pre, "DEBUG value=fuzz-written-value-55c1\n")
	if p := scan(c); len(p) != 1 {
		t.Fatalf("RED PROOF FAILED: a value in a moved pre-restart log gave problems=%v, want exactly 1", p)
	}

	// RED: key bytes in a replica log.
	c = newCluster()
	appendLog(c.Replicas[0].LogPath, "DEBUG dek=planted-dek-bytes-0123456789abcdef\n")
	if p := scan(c); len(p) == 0 {
		t.Fatal("RED PROOF FAILED: raw key bytes in a replica log were NOT flagged")
	}

	// RED: an unreadable (missing) log is a problem, not a silent skip.
	c = newCluster()
	c.addExtraLog(filepath.Join(t.TempDir(), "gone.log"))
	if p := scan(c); len(p) != 1 {
		t.Fatalf("RED PROOF FAILED: a missing log gave problems=%v, want exactly 1", p)
	}
	t.Log("incremental canary scan: red on appended, split, moved-log, key-byte and missing-log cases; green on clean logs")
}

// TestRedProof_AuditVerdict: the verify-audit verdict check must accept only
// the exact VALID verdict (green) and reject BROKEN, INVALID and a report with
// no verdict (red), even when the word VALID appears elsewhere.
func TestRedProof_AuditVerdict(t *testing.T) {
	if !auditVerdictValid("{\n  \"verdict\": \"VALID\",\n  \"chained_events\": 12\n}") {
		t.Fatal("green case misfired: a VALID report was rejected")
	}
	for _, out := range []string{
		"{\n  \"verdict\": \"BROKEN\",\n  \"reason\": \"chain VALID up to id 7\"\n}",
		"{\n  \"verdict\": \"INVALID\"\n}",
		"warning: checkpoint key short; VALID chain unknown",
	} {
		if auditVerdictValid(out) {
			t.Fatalf("RED PROOF FAILED: a non-VALID report passed the verdict check:\n%s", out)
		}
	}
	t.Log("audit verdict check: red on BROKEN / INVALID / no verdict, green on VALID")
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
	if bad, _ := uniquenessViolation(1, 0, 1); bad {
		t.Fatal("green case misfired: exactly one winner + one row was flagged a violation")
	}
	if bad, _ := uniquenessViolation(0, 1, 1); bad {
		t.Fatal("green case misfired: the winner's response was lost in transport but one row exists, flagged a violation")
	}
	if bad, _ := uniquenessViolation(2, 0, 2); !bad {
		t.Fatal("RED PROOF FAILED: two winners + two rows was NOT flagged — the uniqueness oracle is vacuous")
	}
	if bad, _ := uniquenessViolation(1, 0, 2); !bad {
		t.Fatal("RED PROOF FAILED: one ack but two surviving rows was NOT flagged — the uniqueness oracle misses a split-brain insert")
	}
	if bad, _ := uniquenessViolation(0, 0, 0); !bad {
		t.Fatal("RED PROOF FAILED: zero winners was NOT flagged — a total-failure run would pass silently")
	}
	if bad, _ := uniquenessViolation(0, 1, 0); !bad {
		t.Fatal("RED PROOF FAILED: a lost response with zero surviving rows was NOT flagged — a transport error would hide a total failure")
	}
	if bad, _ := uniquenessViolation(2, 1, 2); !bad {
		t.Fatal("RED PROOF FAILED: two winners next to a lost response was NOT flagged — a transport error would hide a double win")
	}
	t.Log("uniqueness oracle: red on two-winners / ack-row mismatch / zero-winners (with or without a lost response), green on exactly-one")
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
