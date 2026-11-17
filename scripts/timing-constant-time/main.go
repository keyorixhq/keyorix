// Command timing-constant-time is a MANUAL, one-off calibrated timing-measurement tool
// (task NH1 / K12). It is NOT a CI test and MUST NOT be wired into CI: it is slow, it is
// sensitive to host load, and its verdicts are advisory. It exists to empirically check the
// constant-time behaviour of Keyorix's secret-comparison leaf primitives with a dudect-style
// statistic (Reparaz, Balasch & Yarom, "Dude, is my code constant time?", DATE 2017).
//
// # WHAT IT MEASURES
//
// For each site below the tool measures the EXACT leaf comparison the production code performs
// (crypto/subtle.ConstantTimeCompare, crypto/hmac.Equal, or golang.org/x/crypto/bcrypt's
// CompareHashAndPassword — the same stdlib/x functions the live call sites use), under two
// interleaved input classes:
//
//	class A ("equal-prefix"): the presented value equals the secret except for its LAST byte,
//	                          so it shares the longest possible common prefix. A byte-by-byte
//	                          short-circuiting comparator would spend the MOST time here.
//	class B ("random"):       the presented value is independent random bytes of the SAME
//	                          length, so it differs near the FRONT on average. A short-circuiting
//	                          comparator would return EARLY here.
//
// Both classes use the same length, so the known-and-accepted length-dependence of
// ConstantTimeCompare (it returns 0 immediately when the lengths differ) is held constant and
// only CONTENT-dependent timing is tested. Measurements are interleaved (the class for each
// measurement is chosen from a per-measurement coin flip) so slow drift in CPU frequency or
// scheduler load affects both classes equally. The statistic is Welch's two-sample t on the
// cropped timing samples; |t| is reported with a verdict. A real non-constant-time site is
// ONLY a finding if |t| is both large AND STABLE across the 3 runs the operator must perform
// (see -runs and the README).
//
// HOST-NOISE CAVEAT (read before trusting any number)
//
// This runs on a shared, thermally-throttled host. A single run's t is noisy. Mitigations,
// all documented and on by default:
//   - run under `nice -n 19` and, if available, pin to one core with `taskset -c <N>` (the
//     tool prints the exact recommended command and refuses to pretend it pinned itself).
//   - each timed measurement batches BATCH identical comparisons in a tight loop, so the
//     per-comparison signal rises above the ~20-40 ns resolution/overhead of the Go monotonic
//     clock. The reported time is per-batch; only the A-vs-B DIFFERENCE matters, not absolutes.
//   - outlier cropping: measurements whose batch time exceeds the CROP-percentile of the
//     combined sample are discarded (preemption / interrupt spikes). The rule and the count
//     dropped are printed.
//   - a warm-up phase (discarded) precedes measurement.
//
// It cannot overcome a loaded host entirely; interpret |t| only as "stable across 3 runs".
//
// USAGE (never in CI)
//
//	cd scripts/timing-constant-time
//	go build -o /tmp/ctt . && taskset -c 2 nice -n 19 /tmp/ctt -n 300000 -runs 1
//	# repeat 3x; a site is a finding only if |t|>=10 in all three.
//
// See README.md in this directory.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// site is one secret-comparison location in the codebase, the leaf primitive it uses, and the
// representative secret length. The Loc/Code fields are documentation that ties the measured
// primitive to the real call site(s) so the table in the report is auditable.
type site struct {
	Name string
	Loc  string // representative production call site(s)
	Prim string // "ct" = subtle.ConstantTimeCompare, "hmac" = hmac.Equal, "bcrypt"
	Len  int    // secret length in bytes (for ct/hmac); ignored for bcrypt
	Note string
}

// sites enumerates every live secret-comparison path found by grep (see the report's K12
// inventory). Sites that share a primitive AND length share a timing property; they are listed
// separately so the mapping to code is explicit, and measured per distinct (primitive,length).
var sites = []site{
	{"api-bearer-token", "server/http/router.go:1645 (metrics); operator/cmd/main.go:214; internal/k8ssync/health.go:139", "ct", 43, "base64 token body after 'Bearer '"},
	{"scim-token", "internal/core/rules/scim_token.go:95; server/middleware/scim.go:28", "ct", 43, "SCIM bearer token"},
	{"csrf-token", "server/middleware/csrf.go:54", "ct", 64, "CSRF double-submit cookie value"},
	{"bootstrap-token", "internal/core/auth_bootstrap.go:271", "ct", 43, "cluster bootstrap token"},
	{"mfa-totp-code", "internal/core/mfa.go:828", "ct", 6, "6-digit TOTP / recovery code"},
	{"recovery-key-hash", "internal/recoverykey/recoverykey.go:141", "ct", 64, "hex-encoded recovery-key hash"},
	{"secret-rotation-noop", "internal/core/secrets.go:765", "ct", 32, "current-vs-new secret value equality"},
	{"audit-seal-mac", "internal/core/audit_seal.go:234; internal/auditverify/seal.go:109; internal/core/audit_key_transition.go:193", "hmac", 64, "hex-encoded HMAC-SHA256 tag"},
	{"backup-manifest-mac", "internal/backupfmt/manifest_sign.go:73", "hmac", 64, "hex HMAC over backup manifest"},
	{"evidence-signing-mac", "internal/core/evidence_signing.go:98", "hmac", 32, "raw HMAC-SHA256 sum"},
	{"keyset-kcv-mac", "internal/pqwrap/keyset.go:299,304,485,515", "hmac", 32, "key-check-value / DEK MAC"},
	{"password-bcrypt", "internal/core/auth.go:76; internal/core/account.go:123", "bcrypt", 0, "bcrypt.CompareHashAndPassword at production cost 12"},
}

func main() {
	n := flag.Int("n", 300_000, "measurements per site (>=200000 required by K12; bcrypt capped, see -bcrypt-n)")
	batch := flag.Int("batch", 400, "comparisons per timed batch (ct/hmac only; raises signal over timer resolution)")
	bcryptN := flag.Int("bcrypt-n", 4000, "measurements for the bcrypt site (200k at cost 12 is multi-hour; see README deviation)")
	bcryptCost := flag.Int("bcrypt-cost", 12, "bcrypt cost to measure (production default is 12)")
	cropPct := flag.Float64("crop", 99.0, "drop batch times above this percentile of the combined sample")
	warmup := flag.Int("warmup", 20_000, "discarded warm-up comparisons per site")
	runs := flag.Int("runs", 1, "repeat the whole suite this many times (K12 requires 3 separate invocations for a finding)")
	only := flag.String("site", "", "measure only the named site (default: all)")
	flag.Parse()

	fmt.Printf("# timing-constant-time (NH1/K12) — dudect-style leakage probe\n")
	fmt.Printf("# time: %s\n", time.Now().UTC().Format(time.RFC3339))
	printEnvironment()
	fmt.Printf("# params: n=%d batch=%d bcrypt-n=%d bcrypt-cost=%d crop=%.1f%% warmup=%d runs=%d\n\n",
		*n, *batch, *bcryptN, *bcryptCost, *cropPct, *warmup, *runs)

	if *n < 200_000 {
		fmt.Printf("WARNING: -n=%d is below the K12 minimum of 200000 interleaved measurements; results are under-powered.\n\n", *n)
	}

	fmt.Printf("%-22s %-7s %-6s %12s %12s %10s  %s\n", "site", "prim", "len", "meanA(ns)", "meanB(ns)", "t", "verdict")
	fmt.Printf("%s\n", dashes(110))

	for r := 1; r <= *runs; r++ {
		if *runs > 1 {
			fmt.Printf("## run %d/%d\n", r, *runs)
		}
		for _, s := range sites {
			if *only != "" && s.Name != *only {
				continue
			}
			var res result
			switch s.Prim {
			case "ct":
				res = measureCompare(s, *n, *batch, *warmup, *cropPct, ctCompare)
			case "hmac":
				res = measureCompare(s, *n, *batch, *warmup, *cropPct, hmacCompare)
			case "bcrypt":
				res = measureBcrypt(s, *bcryptN, *bcryptCost, *cropPct)
			}
			fmt.Printf("%-22s %-7s %-6d %12.1f %12.1f %10.2f  %s\n",
				s.Name, s.Prim, s.Len, res.meanA, res.meanB, res.t, verdict(res.t))
		}
		fmt.Println()
	}

	fmt.Printf("%s\n", dashes(110))
	fmt.Printf("verdict legend: |t|<10 => no content-dependent timing detected (constant-time consistent);\n")
	fmt.Printf("                |t|>=10 => POTENTIAL leak — only a FINDING if stable across 3 separate runs.\n")
	fmt.Printf("note: subtle.ConstantTimeCompare / hmac.Equal are constant-time BY CONSTRUCTION (no early\n")
	fmt.Printf("      return on content); a large stable |t| here would indicate a compiler/host anomaly, not\n")
	fmt.Printf("      a source bug. PAT and machine tokens are NOT measured: they are verified by a SHA-256\n")
	fmt.Printf("      hash DB lookup (GetPersonalAccessTokenByHash), never a byte comparison of the raw token.\n")
	fmt.Printf("      Webhook signing is OUTBOUND (no inbound signature verify exists), so it has no timing\n")
	fmt.Printf("      attack surface and is not measured.\n")
}

type result struct {
	meanA, meanB, t float64
}

// ctCompare is the subtle.ConstantTimeCompare leaf, as the token/CSRF/MFA/recovery sites use it.
func ctCompare(a, b []byte) { _ = subtle.ConstantTimeCompare(a, b) }

// hmacCompare is the hmac.Equal leaf, as the audit/backup/keyset MAC sites use it. hmac.Equal
// is itself a thin wrapper over subtle.ConstantTimeCompare.
func hmacCompare(a, b []byte) { _ = hmac.Equal(a, b) }

// measureCompare runs the dudect loop for a fixed-length byte comparison primitive.
func measureCompare(s site, n, batch, warmup int, cropPct float64, cmp func(a, b []byte)) result {
	secret := randBytes(s.Len)
	// For hex-tag sites, the compared value is hex text; model that by using a hex-encoded
	// secret of the stated length so the comparison width matches production.
	if s.Prim == "hmac" && s.Len == 64 {
		raw := randBytes(32)
		secret = []byte(hex.EncodeToString(raw)) // 64 hex chars
	}

	// Class A: equal-prefix (differs only in the last byte). Class B: independent random.
	mkA := func() []byte {
		c := append([]byte(nil), secret...)
		c[len(c)-1] ^= 0xff
		return c
	}
	mkB := func() []byte { return randBytes(len(secret)) }

	// Warm up (discarded).
	for range warmup {
		cmp(mkA(), secret)
		cmp(mkB(), secret)
	}

	var aTimes, bTimes []float64
	coin := randBytes((n + 7) / 8)
	for i := range n {
		classA := (coin[i/8]>>(uint(i)%8))&1 == 0
		var presented []byte
		if classA {
			presented = mkA()
		} else {
			presented = mkB()
		}
		d := timeBatch(cmp, presented, secret, batch)
		if classA {
			aTimes = append(aTimes, d)
		} else {
			bTimes = append(bTimes, d)
		}
	}
	return welchCropped(aTimes, bTimes, cropPct)
}

// measureBcrypt runs the dudect loop for bcrypt.CompareHashAndPassword. The two classes are a
// password sharing a long common prefix with the real one vs an independent random password;
// bcrypt hashes the FULL input regardless, so both exercise the same work. No batching (one
// compare already dominates the timer). See README for why -bcrypt-n is below 200k.
func measureBcrypt(s site, n, cost int, cropPct float64) result {
	const pw = "C0rrect-Horse-Battery-Staple!"
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt setup: %v\n", err)
		return result{}
	}
	// Class A: equal-prefix wrong password (same length, last char differs).
	a := []byte(pw)
	a[len(a)-1] ^= 0x01
	mkA := func() []byte { return a }
	mkB := func() []byte { return append([]byte("X"), randBytes(len(pw)-1)...) }

	// warm up
	for range 50 {
		_ = bcrypt.CompareHashAndPassword(hash, mkA())
		_ = bcrypt.CompareHashAndPassword(hash, mkB())
	}
	var aTimes, bTimes []float64
	coin := randBytes((n + 7) / 8)
	for i := range n {
		classA := (coin[i/8]>>(uint(i)%8))&1 == 0
		var presented []byte
		if classA {
			presented = mkA()
		} else {
			presented = mkB()
		}
		t0 := time.Now()
		_ = bcrypt.CompareHashAndPassword(hash, presented)
		d := float64(time.Since(t0).Nanoseconds())
		if classA {
			aTimes = append(aTimes, d)
		} else {
			bTimes = append(bTimes, d)
		}
	}
	return welchCropped(aTimes, bTimes, cropPct)
}

// timeBatch times `batch` back-to-back comparisons and returns the batch duration in ns.
func timeBatch(cmp func(a, b []byte), presented, secret []byte, batch int) float64 {
	t0 := time.Now()
	for range batch {
		cmp(presented, secret)
	}
	return float64(time.Since(t0).Nanoseconds())
}

// welchCropped crops outliers above the given percentile of the combined sample, then computes
// Welch's two-sample t and the two cropped means.
func welchCropped(a, b []float64, cropPct float64) result {
	comb := append(append([]float64(nil), a...), b...)
	slices.Sort(comb)
	thr := percentile(comb, cropPct)
	a = cropAbove(a, thr)
	b = cropAbove(b, thr)
	ma, va := meanVar(a)
	mb, vb := meanVar(b)
	na, nb := float64(len(a)), float64(len(b))
	var t float64
	if na > 1 && nb > 1 {
		den := math.Sqrt(va/na + vb/nb)
		if den > 0 {
			t = (ma - mb) / den
		}
	}
	return result{meanA: ma, meanB: mb, t: t}
}

func cropAbove(xs []float64, thr float64) []float64 {
	out := xs[:0:0]
	for _, x := range xs {
		if x <= thr {
			out = append(out, x)
		}
	}
	return out
}

func percentile(sortedAsc []float64, p float64) float64 {
	if len(sortedAsc) == 0 {
		return math.Inf(1)
	}
	idx := int(p / 100 * float64(len(sortedAsc)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sortedAsc) {
		idx = len(sortedAsc) - 1
	}
	return sortedAsc[idx]
}

func meanVar(xs []float64) (mean, variance float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	for _, x := range xs {
		d := x - mean
		variance += d * d
	}
	if len(xs) > 1 {
		variance /= float64(len(xs) - 1)
	}
	return mean, variance
}

func verdict(t float64) string {
	if math.Abs(t) >= 10 {
		return "POTENTIAL LEAK (|t|>=10) — confirm stable across 3 runs"
	}
	if math.Abs(t) >= 4.5 {
		return "borderline (4.5<=|t|<10) — host noise likely; re-run"
	}
	return "ok (constant-time consistent)"
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func dashes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

// printEnvironment prints host hints and whether taskset pinning is in effect (it cannot pin
// itself from inside the process; it reports the recommended command).
func printEnvironment() {
	host := "unknown"
	if h, err := os.Hostname(); err == nil {
		host = h
	}
	taskset := "not found (CPU pinning unavailable)"
	if p, err := exec.LookPath("taskset"); err == nil {
		taskset = p + " (recommended: `taskset -c <core> nice -n 19 ./ctt ...`)"
	}
	fmt.Printf("# host: %s  GOMAXPROCS hint: set GOMAXPROCS=1 for lowest noise\n", host)
	fmt.Printf("# taskset: %s\n", taskset)
}
