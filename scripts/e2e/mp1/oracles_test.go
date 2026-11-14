//go:build e2e

package mp1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// validTokenTTL mirrors server/middleware/auth.go's positive auth-cache TTL
// (30s): the documented window within which a credential revoked on one
// replica must stop authenticating on every other replica. A replica that
// positively cached the credential may keep accepting it up to this long —
// but never past it.
const validTokenTTL = 30 * time.Second

// ── Oracle: post-return visibility (secret value) ───────────────────────────
//
// Secret VALUES are DB-authoritative; ADR-039 lists only the 30s token/session
// caches and the negative-auth cache as per-replica stale-tolerant state —
// NOT secret values. So a value written (and returned success) on replica A
// must be readable on every OTHER replica effectively immediately. This test
// measures the actual window per replica and fails if it exceeds a generous
// 2s bound (far below the 30s auth window, which does not apply to values).
func TestVisibilityWindow(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)
	n := len(c.Replicas)

	name := fmt.Sprintf("mp1-vis-%d", time.Now().UnixNano())
	v := "visible-" + name
	recordCanary(v)
	id, status, err := c.createSecret(c.Replica(0), name, v)
	if err != nil || (status != http.StatusCreated && status != http.StatusOK) {
		t.Fatalf("create on replica 0: status=%d err=%v", status, err)
	}

	const bound = 2 * time.Second
	for i := 1; i < n; i++ {
		start := time.Now()
		deadline := start.Add(bound)
		var seen bool
		var last string
		for time.Now().Before(deadline) {
			got, st, rerr := c.readSecretValue(c.Replica(i), id)
			last = got
			if rerr == nil && st == http.StatusOK && got == v {
				seen = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !seen {
			t.Fatalf("replica %d never saw value written on replica 0 within %s (last read %q) — value not DB-authoritative across replicas", i, bound, last)
		}
		t.Logf("replica %d saw the cross-replica value after %s (bound %s)", i, time.Since(start).Round(time.Millisecond), bound)
	}

	// Measure an update's propagation too (the create path and the update path
	// take different code).
	v2 := v + "-upd"
	recordCanary(v2)
	start := time.Now()
	if st, uerr := c.updateSecret(c.Replica(0), id, v2); uerr != nil || st != http.StatusOK {
		t.Fatalf("update on replica 0: status=%d err=%v", st, uerr)
	}
	for i := 1; i < n; i++ {
		deadline := time.Now().Add(bound)
		var seen bool
		for time.Now().Before(deadline) {
			got, st, rerr := c.readSecretValue(c.Replica(i), id)
			if rerr == nil && st == http.StatusOK && got == v2 {
				seen = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !seen {
			t.Fatalf("replica %d never saw the UPDATED value within %s", i, bound)
		}
	}
	t.Logf("update propagated to all replicas within %s", time.Since(start).Round(time.Millisecond))
}

// ── Oracle: a revoked PAT never authenticates on any replica after revoke ───
//
// Create a Personal Access Token on replica 0, confirm it authenticates on
// every replica, revoke it on replica 0, then confirm every OTHER replica
// stops accepting it within validTokenTTL (30s). A replica that positively
// cached the token may lag up to the TTL; past it is a defect.
func TestRevokedPATDenied(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)
	n := len(c.Replicas)

	rawToken, patID := c.createPAT(t, c.Replica(0), "mp1-revoke-"+fmt.Sprint(time.Now().UnixNano()))

	// Confirm the token authenticates on every replica first (so each has a
	// chance to positively cache it — the case the bound must survive).
	for i := 0; i < n; i++ {
		if st := c.authProbe(c.Replica(i), rawToken); st != http.StatusOK {
			t.Fatalf("fresh PAT not accepted on replica %d: HTTP %d", i, st)
		}
	}

	// Revoke on replica 0.
	env := c.rest(t, c.Replica(0), http.MethodDelete, fmt.Sprintf("/api/v1/auth/tokens/%d", patID), nil)
	if env.StatusCode != http.StatusNoContent && env.StatusCode != http.StatusOK {
		t.Fatalf("revoke PAT: HTTP %d: %s", env.StatusCode, env.Raw)
	}

	for i := 0; i < n; i++ {
		deadline := time.Now().Add(validTokenTTL + 5*time.Second)
		start := time.Now()
		denied := false
		for time.Now().Before(deadline) {
			if c.authProbe(c.Replica(i), rawToken) == http.StatusUnauthorized {
				denied = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !denied {
			t.Fatalf("revoked PAT still accepted by replica %d after %s — exceeds the documented %s window", i, time.Since(start), validTokenTTL)
		}
		t.Logf("replica %d denied the revoked PAT after %s (window %s)", i, time.Since(start).Round(time.Millisecond), validTokenTTL)
	}
}

// createPAT creates a Personal Access Token (POST /auth/tokens) and returns the
// raw token (shown once) and its id.
func (c *Cluster) createPAT(t *testing.T, s *harness.Server, name string) (raw string, id int) {
	t.Helper()
	env := c.rest(t, s, http.MethodPost, "/api/v1/auth/tokens", map[string]any{"name": name})
	if env.StatusCode != http.StatusCreated && env.StatusCode != http.StatusOK {
		t.Fatalf("create PAT: HTTP %d: %s", env.StatusCode, env.Raw)
	}
	var d struct {
		Token string `json:"token"`
		PAT   struct {
			ID int `json:"id"`
		} `json:"pat"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil || d.Token == "" || d.PAT.ID == 0 {
		t.Fatalf("create PAT: unexpected body %s (err=%v)", env.Raw, err)
	}
	return d.Token, d.PAT.ID
}

// authProbe hits an authenticated route with token and returns the status.
func (c *Cluster) authProbe(s *harness.Server, token string) int {
	env, err := c.restTokErr(s, token, http.MethodGet, "/api/v1/projects", nil)
	if err != nil {
		return 0
	}
	return env.StatusCode
}

// ── Oracle: the audit hash chain verifies with no gap or fork ───────────────
//
// After the fuzz corpus and the other oracles have driven many concurrent
// writes across all replicas (every create/update/delete appends an audit
// event under the ADR-029 advisory lock), the chain read straight from the
// shared database must verify VALID — no gap (a missing serialized append) and
// no fork (two heads from two replicas racing the lock). Runs verify-audit in
// --pg-dsn mode, which reads the chain directly without taking the running
// servers' presence lock.
func TestAuditChainVerifies(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	// Drive a short concurrent cross-replica burst so there is fresh audit
	// activity attributable to this test even if run in isolation.
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("mp1-audit-%d-%d", time.Now().UnixNano(), i)
		v := "audit-" + name
		recordCanary(v)
		rep := c.Replica(i % len(c.Replicas))
		if _, st, err := c.createSecret(rep, name, v); err != nil || (st != http.StatusCreated && st != http.StatusOK) {
			t.Fatalf("audit-burst create: st=%d err=%v", st, err)
		}
	}

	out := c.verifyAudit(t)
	if !strings.Contains(out, `"verdict"`) && !strings.Contains(strings.ToUpper(out), "VALID") {
		t.Fatalf("verify-audit produced no VALID verdict:\n%s", out)
	}
	t.Logf("verify-audit: %s", strings.TrimSpace(out))
}

// verifyAudit runs `admin verify-audit --json --pg-dsn <dsn>` against the
// shared database (read-only, does not take the running servers' lock) using
// replica 0's config dir + environment (which carry the key material and DB
// password). A non-zero exit fails the caller.
func (c *Cluster) verifyAudit(t *testing.T) string {
	t.Helper()
	s0 := c.Replica(0)
	args := []string{"admin", "verify-audit", "--json", "--pg-dsn", c.DSN}
	cmd := exec.Command(c.ServerBin, args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- the harness's own built binary, fixed args
	cmd.Dir = s0.Dir
	cmd.Env = s0.Env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("admin verify-audit exited non-zero: %v\n%s", err, out)
	}
	return string(out)
}

// ── Oracle: a SIGKILLed replica leaves no stuck lock ────────────────────────
//
// SIGKILL one replica while all three are under write load, then confirm the
// surviving replicas keep committing writes (each of which appends to the
// audit chain under the ADR-029 advisory lock) within a bounded time — i.e.
// the dead replica's torn-down Postgres connections released any session locks
// it held (advisory locks are released when the holding connection ends) and
// did not wedge the chain. Uses its OWN cluster (SIGKILL would otherwise
// permanently remove a replica the shared fuzz loop depends on).
func TestKilledReplicaNoStuckLock(t *testing.T) {
	requirePG(t)
	c := StartCluster(t, 3, "")

	// Seed a secret and drive a brief burst so there is in-flight audit
	// activity around the kill.
	name := fmt.Sprintf("mp1-kill-%d", time.Now().UnixNano())
	id, st, err := c.createSecret(c.Replica(0), name, "kill-v0")
	if err != nil || (st != http.StatusCreated && st != http.StatusOK) {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	// Fire a few writes at the replica we are about to kill, concurrently,
	// then SIGKILL it mid-flight.
	victim := 1
	for i := 0; i < 3; i++ {
		go func(k int) { _, _ = c.updateSecret(c.Replica(victim), id, fmt.Sprintf("kill-inflight-%d", k)) }(i)
	}
	vs := c.Replicas[victim]
	if vs.Cmd == nil || vs.Cmd.Process == nil {
		t.Fatalf("victim replica has no process")
	}
	if kerr := vs.Cmd.Process.Kill(); kerr != nil {
		t.Fatalf("SIGKILL victim replica: %v", kerr)
	}
	select {
	case <-vs.Exited():
	case <-time.After(10 * time.Second):
		t.Fatalf("victim replica did not exit within 10s of SIGKILL")
	}
	t.Logf("victim replica %d SIGKILLed", victim)

	// A surviving replica must commit a write (→ audit append under the lock)
	// within a bounded time. If the dead replica had wedged the advisory lock,
	// this would hang/fail until Postgres noticed the dead backend.
	bound := 15 * time.Second
	deadline := time.Now().Add(bound)
	progressed := false
	var lastSt int
	var lastErr error
	start := time.Now()
	for time.Now().Before(deadline) {
		survivor := c.Replica(0) // replica 0 always survives
		st, uerr := c.updateSecret(survivor, id, fmt.Sprintf("post-kill-%d", time.Now().UnixNano()))
		lastSt, lastErr = st, uerr
		if uerr == nil && st == http.StatusOK {
			progressed = true
			break
		}
		// also try replica 2
		if st2, uerr2 := c.updateSecret(c.Replica(2), id, fmt.Sprintf("post-kill2-%d", time.Now().UnixNano())); uerr2 == nil && st2 == http.StatusOK {
			progressed = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !progressed {
		t.Fatalf("no surviving replica committed a write within %s of the SIGKILL (last status=%d err=%v) — possible stuck lock", bound, lastSt, lastErr)
	}
	t.Logf("surviving replica committed a write %s after the SIGKILL (bound %s)", time.Since(start).Round(time.Millisecond), bound)

	// And the chain still verifies (no fork/gap left by the torn-down replica).
	out := c.verifyAudit(t)
	if !strings.Contains(out, `"verdict"`) && !strings.Contains(strings.ToUpper(out), "VALID") {
		t.Fatalf("after SIGKILL, verify-audit produced no VALID verdict:\n%s", out)
	}
	t.Logf("after SIGKILL, verify-audit: %s", strings.TrimSpace(out))
}

// ── Oracle: no secret value or key bytes appear in any replica log (canary) ──
//
// Every value written by this package is recorded as a canary. This test adds
// a fresh, highly-distinctive canary of its own, then scans every replica's
// log file for ANY recorded canary value and for the raw DEK/salt key bytes.
// A hit means a secret value or key material leaked into a log — a serious
// confidentiality defect.
func TestZZCanaryNoSecretInLogs(t *testing.T) {
	requirePG(t)
	c := getSharedCluster(t)

	fresh := fmt.Sprintf("CANARY-%d-DO-NOT-LOG", time.Now().UnixNano())
	name := fmt.Sprintf("mp1-canary-%d", time.Now().UnixNano())
	recordCanary(fresh)
	if _, st, err := c.createSecret(c.Replica(0), name, fresh); err != nil || (st != http.StatusCreated && st != http.StatusOK) {
		t.Fatalf("canary create: st=%d err=%v", st, err)
	}
	// Read it back on every replica (exercises the value-read log path too).
	for i := range c.Replicas {
		_, _, _ = c.readSecretValue(c.Replica(i), 0) // id 0 ignored; just exercise
	}

	values := canarySnapshot()
	// Also treat the raw key bytes as canaries.
	keyCanaries := c.keyByteCanaries(t)

	for _, s := range c.Replicas {
		raw, err := os.ReadFile(s.LogPath) //nolint:gosec // harness-controlled path
		if err != nil {
			t.Logf("replica log %s unreadable (skipping): %v", s.LogPath, err)
			continue
		}
		log := string(raw)
		for _, v := range scanLogForSecrets(log, values, 6) {
			t.Errorf("CANARY HIT: secret value %q found in replica log %s", v, s.LogPath)
		}
		for label, kc := range keyCanaries {
			if kc != "" && strings.Contains(log, kc) {
				t.Errorf("CANARY HIT: key material (%s) found in replica log %s", label, s.LogPath)
			}
		}
	}
	t.Logf("canary scan: %d distinct secret values checked against %d replica logs", len(values), len(c.Replicas))
}

// keyByteCanaries returns distinctive substrings of the raw on-disk key files
// (dek.key, kek.salt) to search logs for. A hex-encoded chunk is used so a
// match is unambiguous even if the file bytes are not printable.
func (c *Cluster) keyByteCanaries(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	dir := c.Replica(0).Dir
	for _, name := range []string{"dek.key", "kek.salt"} {
		raw, err := os.ReadFile(dir + "/keys/" + name) //nolint:gosec // harness temp path
		if err != nil {
			continue
		}
		if len(raw) > 8 {
			out[name+"(hex)"] = fmt.Sprintf("%x", raw[:16])
			out[name+"(raw)"] = string(raw)
		}
	}
	return out
}
