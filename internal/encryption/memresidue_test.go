package encryption

// memresidue_test.go (#4498): a subprocess memory-residue oracle for the DEK
// and KEK after Service.Shutdown. It MEASURES: it counts the copies left in
// process memory, fails on a copy that has a documented zeroization claim, and
// holds every other count to a ratchet. It does not claim that no key bytes
// remain in memory.
//
// Needles: the raw DEK and KEK, the KEK's hex and base64 (standard and
// URL-safe, unpadded, so a padded copy matches too) text, and the master
// passphrase. Scenarios (memResidueScenarios), one child each: the "file" key
// provider with a raw, hex, base64 and URL-safe base64 KEK file, and the
// passphrase ("password") provider, the default config.
//
// atrest_memory_canary_fuzz_test.go Part B asserts the narrow claim
// (EncryptionService.IsDEKWiped) and says why it cannot scan memory itself: an
// in-process scan cannot tell product residue from the harness's own copy of the
// needle. This oracle closes that gap. (1) The child holds each needle only as a
// masked 8-byte prefix plus a SHA-256 of the whole key, so the scanner's own
// state is never a match. (2) Live control: before Shutdown the scan must find
// the DEK at the address of the claimed copy (EncryptionService.dek); a scanner
// that finds nothing there proves nothing afterwards. (3) Red control: a second
// child zeroes only that product copy (WipeDEK) and the scan must then find 0
// hits at its address and exactly that many fewer DEK hits overall, so every
// count moves with product memory, not with the harness.
//
// Verdict (memResidueVerdict, unit-tested on every platform by
// TestMemResidueVerdict):
//   - a hit after Shutdown at a claimed address fails (today the one claim is
//     INV-ENCRYPTION-24, EncryptionService.dek);
//   - any other hit is hardening data: it is logged and counted per key kind,
//     and the count may not exceed memResidueRatchet[scenario][kind]. The
//     ratchet only goes down: when a copy is attributed and wiped, lower the
//     bound in the same PR. A count below the bound is logged as a candidate
//     new bound.
//   - a copy that is made and dropped inside one call has no address the child
//     can know in advance; its claim names the allocating function instead
//     (memResidueSiteClaims) and is checked by the attribution child (GC off,
//     so nothing is freed and reused): no needle allocated under that function
//     may be found after Shutdown, and the function must appear in some
//     sampled allocation stack (else the claim would be vacuous).
//
// The child is this test binary re-executed (as keymanager_subprocess_crash_test.go
// does) and scans its own /proc/self/mem; the parent reads the verdict. Linux
// only: memScanSupported skips cleanly elsewhere (macOS has no /proc, and
// mach_vm_read on a task port needs entitlements) and where /proc/self/mem is
// not readable. Long lane: skipped under -short and unless
// KEYORIX_MEMRESIDUE_ORACLE=1, so neither the quick tier nor the merge-queue
// suite pays for the child processes:
//
//	KEYORIX_MEMRESIDUE_ORACLE=1 go test ./internal/encryption/ -run '^TestKeyMaterialAbsentFromProcessMemoryAfterShutdown$' -count=1 -v
//
// What it does NOT cover: swap or core files, the kernel, copies the Go runtime
// moved when it grew a stack (an old stack copy can survive until reused), keys
// derived from the KEK (evidence/audit/backup HKDF keys), key providers other
// than "file" and "password" (env, exec, KMS, TPM, Shamir), upper-case hex, KEK
// files larger than io.ReadAll's first buffer (512 bytes: a grown buffer leaves
// its predecessor behind), and rotation/rewrap (one Initialize + Shutdown
// lifecycle only).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
)

const (
	envMemResidueOracle   = "KEYORIX_MEMRESIDUE_ORACLE"   // opts in to the long-lane oracle
	envMemResidueHelper   = "KEYORIX_MEMRESIDUE_HELPER"   // set by the parent: the child's key directory
	envMemResidueMode     = "KEYORIX_MEMRESIDUE_MODE"     // set by the parent: memResidueModeMeasure or memResidueModeRed
	envMemResidueScenario = "KEYORIX_MEMRESIDUE_SCENARIO" // set by the parent: a memResidueScenarios name
	memResidueMarker      = "MEMRESIDUE "

	memResidueModeMeasure = "measure" // live scan, Shutdown, GC, scan again
	memResidueModeRed     = "red"     // live scan, WipeDEK on the claimed copy only, scan again
)

// memResidueScenario is one key-provider configuration the oracle runs.
// kekFile renders the KEK as the "file" provider's file content; a nil kekFile
// selects the passphrase provider.
type memResidueScenario struct {
	name    string
	kekFile func(kek []byte) []byte
}

// Each kekFile allocates its result once, at its final size: a buffer grown by
// append would leave an unwiped copy of the text behind in the harness.
var memResidueScenarios = []memResidueScenario{
	{"file-raw", bytes.Clone},
	{"file-hex", func(k []byte) []byte {
		return append(hex.AppendEncode(make([]byte, 0, hex.EncodedLen(len(k))+1), k), '\n')
	}},
	{"file-base64", func(k []byte) []byte {
		return append(base64.StdEncoding.AppendEncode(make([]byte, 0, base64.StdEncoding.EncodedLen(len(k))+1), k), '\n')
	}},
	{"file-base64url", func(k []byte) []byte {
		return base64.RawURLEncoding.AppendEncode(make([]byte, 0, base64.RawURLEncoding.EncodedLen(len(k))), k)
	}},
	{"passphrase", nil},
}

func memResidueScenarioNamed(name string) (memResidueScenario, bool) {
	i := slices.IndexFunc(memResidueScenarios, func(s memResidueScenario) bool { return s.name == name })
	if i < 0 {
		return memResidueScenario{}, false
	}
	return memResidueScenarios[i], true
}

// memResidueRatchet is the upper bound, per scenario and needle kind, on
// copies still in process memory after Shutdown that carry no zeroization
// claim. It may only go DOWN. The count varies run to run (the allocator reuses
// freed slots); the bound is the maximum over repeated runs, so lower it only
// when repeated runs never reach it. A scenario or kind missing here fails.
//
// Recorded on Linux x86_64, go1.27, one first-boot Initialize + Shutdown per
// scenario. Attributed with TestMemResidueAttribute
// (memresidue_attribute_linux_test.go). The raw dek/kek copies are state inside
// the Go crypto packages, which application code has no API to zero (the same
// in every scenario):
//
//	dek 1  crypto/aes.NewCipher key schedule      <- aead.NewEncryptionService
//	dek 1  crypto/cipher GCM copy of the block    <- aead.NewEncryptionService
//	kek 2  crypto/aes.NewCipher key schedule      <- wrapKey (first boot), unwrapKey
//	kek 2  crypto/cipher GCM copy of the block    <- wrapKey (first boot), unwrapKey
//	kek 6  crypto/sha256 buffer in HKDF's HMAC    <- deriveEvidenceSignKey, deriveAuditCheckpointKey,
//	       (Extract writes the KEK as the message)   auditverify.DeriveBackupManifestKey (key + key ID each)
//
// The encoded and passphrase copies, per scenario:
//
//	kek-hex/-base64/-base64url 1  io.ReadAll's buffer         <- crypto.(*FileKeyProvider).KEK (app-owned, unwiped)
//	kek-hex/-base64/-base64url 1  string(material)            <- crypto.decodeKeyMaterial (immutable string)
//	passphrase 1  the string passed to Service.Initialize, kept as PasswordKeyProvider.passphrase (immutable)
//	passphrase 1  string(password) in golang.org/x/crypto/pbkdf2.Key
//	passphrase 1  []byte(password) in crypto/internal/fips140/pbkdf2.Key (for hmac.New)
//
// The application-held copies on this path are wiped before or at Shutdown and
// are not counted: the provider's returned KEK is KeyManager.Initialize's kek
// (defer wipeBytes), the unwrapped DEK is km.currentDEK (KeyManager.Wipe), and
// Service.initialize's GetDEK copy is the slice EncryptionService.dek keeps
// (WipeDEK, the claimed copy).
var memResidueRatchet = map[string]map[string]int{
	"file-raw":       {"dek": 2, "kek": 10, "kek-hex": 0, "kek-base64": 0, "kek-base64url": 0, "passphrase": 0},
	"file-hex":       {"dek": 2, "kek": 10, "kek-hex": 2, "kek-base64": 0, "kek-base64url": 0, "passphrase": 0},
	"file-base64":    {"dek": 2, "kek": 10, "kek-hex": 0, "kek-base64": 2, "kek-base64url": 0, "passphrase": 0},
	"file-base64url": {"dek": 2, "kek": 10, "kek-hex": 0, "kek-base64": 0, "kek-base64url": 2, "passphrase": 0},
	"passphrase":     {"dek": 2, "kek": 10, "kek-hex": 0, "kek-base64": 0, "kek-base64url": 0, "passphrase": 3},
}

// memResidueSiteClaim is a zeroization claim on every copy allocated under one
// function (Func, a full runtime function name): no needle allocated there may
// survive Shutdown, in the listed scenarios. Checked by the attribution child.
type memResidueSiteClaim struct {
	Scenarios []string
	Func      string
	What      string
	Claim     string
}

// memResidueSiteClaims lists the site claims.
var memResidueSiteClaims = []memResidueSiteClaim{}

// memResidueClaim is a copy with a documented zeroization claim: a hit at its
// address after Shutdown is a failure, not hardening data.
type memResidueClaim struct {
	Kind  string `json:"kind"`
	What  string `json:"what"`
	Claim string `json:"claim"`
	Addr  uint64 `json:"addr"`
}

// memNeedle identifies a secret without storing it: masked is the first 8 bytes
// XOR mask, sum is SHA-256 of the full value.
type memNeedle struct {
	name         string
	length       int
	mask, masked uint64
	sum          [32]byte
}

type memHit struct {
	Name   string `json:"name"`
	Region string `json:"region"`
	Addr   uint64 `json:"addr"`
}

type memResidueReport struct {
	Mode        string            `json:"mode"`
	Scenario    string            `json:"scenario"`
	Claims      []memResidueClaim `json:"claims"`
	LiveHits    []memHit          `json:"live_hits"`
	AfterHits   []memHit          `json:"after_hits"`
	ScannedLive uint64            `json:"scanned_live"`
	ScannedPost uint64            `json:"scanned_post"`
	Error       string            `json:"error,omitempty"`
}

// memAttributedHit is a hit with what holds it: Holder describes the heap
// object, stack frame or segment, Stack is the heap object's allocation stack
// (full function names, innermost first; empty when not a sampled heap object).
type memAttributedHit struct {
	memHit
	Phase  string   `json:"phase"` // "live" or "after"
	Holder string   `json:"holder"`
	Stack  []string `json:"stack,omitempty"`
}

// memAttributionReport is the attribution child's report. SitesSeen records,
// per site claim of the scenario, whether that function occurs in any sampled
// allocation stack.
type memAttributionReport struct {
	Scenario  string             `json:"scenario"`
	Claims    []memResidueClaim  `json:"claims"`
	Hits      []memAttributedHit `json:"hits"`
	SitesSeen map[string]bool    `json:"sites_seen"`
	Error     string             `json:"error,omitempty"`
}

func siteClaimsFor(claims []memResidueSiteClaim, scenario string) []memResidueSiteClaim {
	var out []memResidueSiteClaim
	for _, c := range claims {
		if slices.Contains(c.Scenarios, scenario) {
			out = append(out, c)
		}
	}
	return out
}

// memResidueSiteVerdict applies the site claims to an attribution report: a
// needle allocated under a claimed function and found after Shutdown fails, and
// so does a claim whose function was never seen allocating (a renamed or
// removed function would otherwise pass vacuously).
func memResidueSiteVerdict(rep memAttributionReport, claims []memResidueSiteClaim) (failures []string) {
	for _, c := range siteClaimsFor(claims, rep.Scenario) {
		if !rep.SitesSeen[c.Func] {
			failures = append(failures, fmt.Sprintf("site claim %s is vacuous: no sampled allocation under %s in scenario %s", c.Claim, c.Func, rep.Scenario))
			continue
		}
		for _, h := range rep.Hits {
			if h.Phase == "after" && slices.Contains(h.Stack, c.Func) {
				failures = append(failures, fmt.Sprintf("CLAIMED COPY NOT WIPED: %s at %#x after Shutdown, allocated under %s (%s), contradicting %s", h.Name, h.Addr, c.Func, c.What, c.Claim))
			}
		}
	}
	return failures
}

func newMemNeedle(name string, secret []byte) memNeedle {
	var m [8]byte
	_, _ = rand.Read(m[:])
	mask := binary.LittleEndian.Uint64(m[:])
	return memNeedle{
		name: name, length: len(secret), mask: mask,
		masked: binary.LittleEndian.Uint64(secret[:8]) ^ mask,
		sum:    sha256.Sum256(secret),
	}
}

func countHits(hits []memHit, match func(memHit) bool) int {
	n := 0
	for _, h := range hits {
		if match(h) {
			n++
		}
	}
	return n
}

// memResidueVerdict applies the measure-mode rules to a child report. failures
// fail the test; notes are logged (hardening data and ratchet hints).
func memResidueVerdict(rep memResidueReport, ratchet map[string]int) (failures, notes []string) {
	if len(rep.Claims) == 0 {
		return []string{"child reported no claimed copies: the live control has nothing to find"}, nil
	}
	claimed := map[uint64]memResidueClaim{}
	for _, c := range rep.Claims {
		claimed[c.Addr] = c
		if countHits(rep.LiveHits, func(h memHit) bool { return h.Name == c.Kind && h.Addr == c.Addr }) == 0 {
			failures = append(failures, fmt.Sprintf("scanner is blind: the live %s was not found at %s (%#x) before Shutdown (%d bytes scanned); a clean post-Shutdown result would prove nothing", c.Kind, c.What, c.Addr, rep.ScannedLive))
		}
	}
	// Every scenario leaves raw KEK copies in Go's crypto state while the
	// service runs; none found live means the harness's KEK needle is not the
	// product's KEK, and every KEK count afterwards would be vacuous.
	if countHits(rep.LiveHits, func(h memHit) bool { return h.Name == "kek" }) == 0 {
		failures = append(failures, "scanner found no live kek copy before Shutdown: the needle does not match the product's KEK")
	}
	perKind := map[string]int{}
	for _, h := range rep.AfterHits {
		if c, ok := claimed[h.Addr]; ok && c.Kind == h.Name {
			failures = append(failures, fmt.Sprintf("CLAIMED COPY NOT WIPED: %s bytes still at %s (%#x) after Shutdown, contradicting %s", h.Name, c.What, h.Addr, c.Claim))
			continue
		}
		perKind[h.Name]++
		notes = append(notes, fmt.Sprintf("residue (no zeroization claim): %s at %#x (%s)", h.Name, h.Addr, h.Region))
	}
	kinds := make([]string, 0, len(perKind)+len(ratchet))
	for k := range perKind {
		kinds = append(kinds, k)
	}
	for k := range ratchet {
		if _, ok := perKind[k]; !ok {
			kinds = append(kinds, k)
		}
	}
	slices.Sort(kinds)
	for _, k := range kinds {
		bound, ok := ratchet[k]
		n := perKind[k]
		switch {
		case !ok:
			failures = append(failures, fmt.Sprintf("RATCHET: %d unclaimed %s copies after Shutdown and no memResidueRatchet entry for %q", n, k, k))
		case n > bound:
			failures = append(failures, fmt.Sprintf("RATCHET REGRESSION: %d unclaimed %s copies after Shutdown, bound is %d", n, k, bound))
		case n < bound:
			notes = append(notes, fmt.Sprintf("ratchet: %d unclaimed %s copies, bound %d; if repeated runs never exceed %d, lower memResidueRatchet[%q] to %d", n, k, bound, n, k, n))
		default:
			notes = append(notes, fmt.Sprintf("ratchet: %d unclaimed %s copies, at the bound", n, k))
		}
	}
	return failures, notes
}

// memResidueRedVerdict checks the red control: zeroing exactly the claimed copy
// removes every hit at its address and nothing else.
func memResidueRedVerdict(rep memResidueReport) (failures []string) {
	if len(rep.Claims) == 0 {
		return []string{"red control: child reported no claimed copies"}
	}
	for _, c := range rep.Claims {
		at := func(h memHit) bool { return h.Name == c.Kind && h.Addr == c.Addr }
		kind := func(h memHit) bool { return h.Name == c.Kind }
		liveAt := countHits(rep.LiveHits, at)
		if liveAt == 0 {
			failures = append(failures, fmt.Sprintf("red control: live %s not found at %s (%#x)", c.Kind, c.What, c.Addr))
			continue
		}
		if n := countHits(rep.AfterHits, at); n != 0 {
			failures = append(failures, fmt.Sprintf("red control: %d hit(s) at %s (%#x) after zeroing it", n, c.What, c.Addr))
		}
		before, after := countHits(rep.LiveHits, kind), countHits(rep.AfterHits, kind)
		if after != before-liveAt {
			failures = append(failures, fmt.Sprintf("red control: %s hits went %d -> %d after zeroing the one copy at %#x (want %d): the count does not track product memory", c.Kind, before, after, c.Addr, before-liveAt))
		}
	}
	return failures
}

// runMemResidueTestChild re-executes this test binary running only testName,
// with the child's environment, and decodes the report line it prints into rep.
func runMemResidueTestChild(t *testing.T, testName, scenario string, env []string, rep any) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.count=1") // #nosec G204 -- os.Args[0] is this test binary
	cmd.Env = append(os.Environ(), envMemResidueHelper+"="+t.TempDir(), envMemResidueScenario+"="+scenario)
	cmd.Env = append(cmd.Env, env...)
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() { out, runErr = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("memory-residue child %s (%s) exceeded 2m", testName, scenario)
	}
	found := false
	for line := range strings.SplitSeq(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, memResidueMarker); ok {
			if err := json.Unmarshal([]byte(rest), rep); err != nil {
				t.Fatalf("bad child report %q: %v", rest, err)
			}
			found = true
		}
	}
	if !found || runErr != nil {
		t.Fatalf("child %s (%s) failed: err=%v found=%v output:\n%.2000s", testName, scenario, runErr, found, out)
	}
}

// runMemResidueChild runs TestMemResidueHelperProcess in the given mode and
// scenario and returns its report.
func runMemResidueChild(t *testing.T, mode, scenario string) memResidueReport {
	t.Helper()
	var rep memResidueReport
	runMemResidueTestChild(t, "TestMemResidueHelperProcess", scenario, []string{envMemResidueMode + "=" + mode}, &rep)
	if rep.Error != "" || rep.Mode != mode || rep.Scenario != scenario {
		t.Fatalf("child (%s, %s) failed: report-error=%q mode=%q scenario=%q", mode, scenario, rep.Error, rep.Mode, rep.Scenario)
	}
	return rep
}

// runMemAttributionChild runs TestMemResidueAttributeChild (Linux only) in the
// given scenario and returns its report.
func runMemAttributionChild(t *testing.T, scenario string) memAttributionReport {
	t.Helper()
	var rep memAttributionReport
	runMemResidueTestChild(t, "TestMemResidueAttributeChild", scenario, nil, &rep)
	if rep.Error != "" || rep.Scenario != scenario {
		t.Fatalf("attribution child (%s) failed: report-error=%q scenario=%q", scenario, rep.Error, rep.Scenario)
	}
	return rep
}

func TestKeyMaterialAbsentFromProcessMemoryAfterShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child test processes and scans their memory; skipped under -short")
	}
	if os.Getenv(envMemResidueOracle) == "" {
		t.Skip("long-lane oracle: set " + envMemResidueOracle + "=1 to run it")
	}
	if err := memScanSupported(); err != nil {
		t.Skipf("memory-residue oracle unavailable: %v", err)
	}

	t.Run("red-control", func(t *testing.T) {
		rep := runMemResidueChild(t, memResidueModeRed, "file-raw")
		for _, f := range memResidueRedVerdict(rep) {
			t.Error(f)
		}
		t.Logf("red control: dek hits %d live, %d after zeroing the claimed copy", countHits(rep.LiveHits, func(h memHit) bool { return h.Name == "dek" }), countHits(rep.AfterHits, func(h memHit) bool { return h.Name == "dek" }))
	})

	t.Run("after-shutdown", func(t *testing.T) {
		for _, sc := range memResidueScenarios {
			t.Run(sc.name, func(t *testing.T) {
				rep := runMemResidueChild(t, memResidueModeMeasure, sc.name)
				t.Logf("scanned %d bytes live, %d after Shutdown; live hits %d, after hits %d", rep.ScannedLive, rep.ScannedPost, len(rep.LiveHits), len(rep.AfterHits))
				failures, notes := memResidueVerdict(rep, memResidueRatchet[sc.name])
				for _, n := range notes {
					t.Log(n)
				}
				for _, f := range failures {
					t.Error(f)
				}
			})
		}
	})

	t.Run("site-claims", func(t *testing.T) {
		for _, sc := range memResidueScenarios {
			if len(siteClaimsFor(memResidueSiteClaims, sc.name)) == 0 {
				continue
			}
			t.Run(sc.name, func(t *testing.T) {
				rep := runMemAttributionChild(t, sc.name)
				for _, f := range memResidueSiteVerdict(rep, memResidueSiteClaims) {
					t.Error(f)
				}
			})
		}
	})
}

// TestMemResidueHelperProcess is the child: it does nothing unless the parent
// set KEYORIX_MEMRESIDUE_HELPER (to a scratch key directory).
func TestMemResidueHelperProcess(t *testing.T) {
	dir := os.Getenv(envMemResidueHelper)
	if dir == "" {
		t.Skip("not invoked as the memory-residue child")
	}
	rep := memResidueReport{Mode: os.Getenv(envMemResidueMode), Scenario: os.Getenv(envMemResidueScenario)}
	fail := func(format string, a ...any) {
		rep.Error = fmt.Sprintf(format, a...)
		emitMemResidue(rep)
	}
	if rep.Mode != memResidueModeMeasure && rep.Mode != memResidueModeRed {
		fail("unknown mode %q", rep.Mode)
		return
	}
	sc, ok := memResidueScenarioNamed(rep.Scenario)
	if !ok {
		fail("unknown scenario %q", rep.Scenario)
		return
	}
	svc, needles, claims, err := startMemResidueService(dir, sc)
	if err != nil {
		fail("%v", err)
		return
	}
	rep.Claims = claims

	if rep.LiveHits, rep.ScannedLive, err = scanProcessMemory(needles); err != nil {
		fail("live scan: %v", err)
		return
	}
	if rep.Mode == memResidueModeRed {
		svc.encryptionService.WipeDEK() // zero the claimed copy only; no Shutdown, no GC
	} else {
		svc.Shutdown()
		runtime.GC() // collection does not zero freed memory; this only drops reachable copies
	}
	if rep.AfterHits, rep.ScannedPost, err = scanProcessMemory(needles); err != nil {
		fail("second scan: %v", err)
		return
	}
	if rep.Mode == memResidueModeRed {
		svc.Shutdown()
	}
	emitMemResidue(rep)
}

// kekNeedles returns the needles for a KEK: its raw bytes and its hex, base64
// and URL-safe base64 text (unpadded, so they match padded text too). The
// URL-safe needle is left out when it equals the standard one, so one copy is
// never counted twice. The encoded text is wiped before returning.
func kekNeedles(kek []byte) []memNeedle {
	hx := hex.AppendEncode(nil, kek)
	std := base64.RawStdEncoding.AppendEncode(nil, kek)
	url := base64.RawURLEncoding.AppendEncode(nil, kek)
	defer wipeBytes(hx)
	defer wipeBytes(std)
	defer wipeBytes(url)
	needles := []memNeedle{newMemNeedle("kek", kek), newMemNeedle("kek-hex", hx), newMemNeedle("kek-base64", std)}
	if !bytes.Equal(std, url) {
		needles = append(needles, newMemNeedle("kek-base64url", url))
	}
	return needles
}

// startMemResidueService runs the lifecycle under test up to the live scan for
// scenario sc: a random KEK in a "file" key-provider file in the scenario's
// encoding, or a random passphrase for the passphrase provider; then a
// first-boot Initialize. It returns the needles (masked; the plain key bytes,
// text and passphrase it held are wiped) and the claimed copies' addresses.
func startMemResidueService(dir string, sc memResidueScenario) (*Service, []memNeedle, []memResidueClaim, error) {
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	var needles []memNeedle
	var svc *Service
	if sc.kekFile != nil {
		// A KEK whose standard and URL-safe base64 differ, so the URL-safe file
		// takes the URL-safe decode branch and both needles are distinct.
		kek := make([]byte, 32)
		text := make([]byte, base64.RawStdEncoding.EncodedLen(len(kek)))
		for {
			if _, err := rand.Read(kek); err != nil {
				return nil, nil, nil, fmt.Errorf("rand: %w", err)
			}
			base64.RawStdEncoding.Encode(text, kek)
			if bytes.ContainsAny(text, "+/") {
				break
			}
		}
		wipeBytes(text)
		content := sc.kekFile(kek)
		kekPath := filepath.Join(dir, "kek.bin")
		err := os.WriteFile(kekPath, content, 0o600)
		wipeBytes(content)
		if err != nil {
			wipeBytes(kek)
			return nil, nil, nil, fmt.Errorf("write kek: %w", err)
		}
		needles = kekNeedles(kek)
		wipeBytes(kek)
		cfg.KeyProvider = config.KeyProviderConfig{Type: "file", FilePath: kekPath}
		svc = NewService(cfg, dir)
		if err := svc.Initialize(""); err != nil {
			return nil, nil, nil, fmt.Errorf("initialize: %w", err)
		}
	} else {
		// The passphrase reaches the product as a Go string (Service.Initialize's
		// parameter, kept as PasswordKeyProvider.passphrase): immutable, so this
		// string is the product's copy and stays; the harness wipes its bytes.
		// 48 characters: longer than the runtime's 32-byte stack buffer for a
		// string <-> []byte conversion (so such copies land on the heap, as for
		// a typical passphrase) and shorter than HMAC-SHA256's 64-byte block.
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, nil, fmt.Errorf("rand: %w", err)
		}
		pp := hex.AppendEncode(nil, raw)
		wipeBytes(raw)
		passphrase := string(pp)
		cfg.KeyProvider = config.KeyProviderConfig{Type: "password"}
		svc = NewService(cfg, dir)
		if err := svc.Initialize(passphrase); err != nil {
			wipeBytes(pp)
			return nil, nil, nil, fmt.Errorf("initialize: %w", err)
		}
		// Re-derive the KEK from the salt the first boot wrote, as the provider
		// does. Not through crypto/pbkdf2: it copies the password into a buffer
		// of its own that the harness could not wipe.
		salt, err := os.ReadFile(filepath.Join(dir, cfg.SaltPath)) // #nosec G304 -- under the parent's t.TempDir
		if err != nil {
			wipeBytes(pp)
			return nil, nil, nil, fmt.Errorf("read salt: %w", err)
		}
		kek := memPBKDF2SHA256(pp, salt, crypto.PBKDF2Iterations)
		needles = append(kekNeedles(kek), newMemNeedle("passphrase", pp))
		wipeBytes(kek)
		wipeBytes(pp)
	}
	dek := svc.keyManager.GetDEK()
	needles = append(needles, newMemNeedle("dek", dek))
	wipeBytes(dek)

	// The claimed copy's address. dek is unexported in package aead; reflect
	// reads the slice's data pointer without copying the bytes.
	claims := []memResidueClaim{{
		Kind: "dek", What: "EncryptionService.dek", Claim: "INV-ENCRYPTION-24",
		Addr: uint64(reflect.ValueOf(svc.encryptionService).Elem().FieldByName("dek").Pointer()),
	}}
	return svc, needles, claims, nil
}

// memPBKDF2SHA256 is PBKDF2-HMAC-SHA256 with one 32-byte output block, the
// passphrase provider's KDF. crypto/hmac keeps the key only XORed into its
// pads, so the passphrase leaves no raw copy here.
func memPBKDF2SHA256(pass, salt []byte, iter int) []byte {
	prf := hmac.New(sha256.New, pass)
	prf.Write(salt)
	prf.Write([]byte{0, 0, 0, 1})
	t := prf.Sum(nil)
	u := slices.Clone(t)
	for range iter - 1 {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(u[:0])
		for i := range t {
			t[i] ^= u[i]
		}
	}
	wipeBytes(u)
	return t
}

func emitMemResidue(rep memResidueReport) {
	b, _ := json.Marshal(rep)
	fmt.Println(memResidueMarker + string(b))
}
