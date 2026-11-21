package encryption

// memresidue_test.go (#4498): a subprocess memory-residue oracle for the raw
// DEK and KEK bytes after Service.Shutdown. It MEASURES: it counts the copies
// left in process memory, fails on a copy that has a documented zeroization
// claim, and holds every other count to a ratchet. It does not claim that no
// key bytes remain in memory.
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
//     and the count may not exceed memResidueRatchet[kind]. The ratchet only
//     goes down: when a copy is attributed and wiped, lower the bound in the
//     same PR. A count below the bound is logged as a candidate new bound.
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
// than "file", and rotation/rewrap (one Initialize + Shutdown lifecycle only).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
)

const (
	envMemResidueOracle = "KEYORIX_MEMRESIDUE_ORACLE" // opts in to the long-lane oracle
	envMemResidueHelper = "KEYORIX_MEMRESIDUE_HELPER" // set by the parent: the child's key directory
	envMemResidueMode   = "KEYORIX_MEMRESIDUE_MODE"   // set by the parent: memResidueModeMeasure or memResidueModeRed
	memResidueMarker    = "MEMRESIDUE "

	memResidueModeMeasure = "measure" // live scan, Shutdown, GC, scan again
	memResidueModeRed     = "red"     // live scan, WipeDEK on the claimed copy only, scan again
)

// memResidueRatchet is the upper bound, per key kind, on copies of the raw key
// still in process memory after Shutdown that carry no zeroization claim. It
// may only go DOWN. The count varies run to run (the allocator reuses freed
// slots); the bound is the maximum over repeated runs, so lower it only when
// repeated runs never reach it.
//
// Recorded on Linux x86_64, go1.27, file key provider, one first-boot
// Initialize + Shutdown. Attributed with TestMemResidueAttribute
// (memresidue_attribute_linux_test.go); every copy is state inside the Go
// crypto packages, which application code has no API to zero:
//
//	dek 1  crypto/aes.NewCipher key schedule      <- aead.NewEncryptionService
//	dek 1  crypto/cipher GCM copy of the block    <- aead.NewEncryptionService
//	kek 2  crypto/aes.NewCipher key schedule      <- wrapKey (first boot), unwrapKey
//	kek 2  crypto/cipher GCM copy of the block    <- wrapKey (first boot), unwrapKey
//	kek 6  crypto/sha256 buffer in HKDF's HMAC    <- deriveEvidenceSignKey, deriveAuditCheckpointKey,
//	       (Extract writes the KEK as the message)   auditverify.DeriveBackupManifestKey (key + key ID each)
//
// The application-held copies on this path are wiped before or at Shutdown and
// are not counted: the provider's read buffer is KeyManager.Initialize's kek
// (defer wipeBytes), the unwrapped DEK is km.currentDEK (KeyManager.Wipe), and
// Service.initialize's GetDEK copy is the slice EncryptionService.dek keeps
// (WipeDEK, the claimed copy).
var memResidueRatchet = map[string]int{
	"dek": 2,
	"kek": 10,
}

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
	Claims      []memResidueClaim `json:"claims"`
	LiveHits    []memHit          `json:"live_hits"`
	AfterHits   []memHit          `json:"after_hits"`
	ScannedLive uint64            `json:"scanned_live"`
	ScannedPost uint64            `json:"scanned_post"`
	Error       string            `json:"error,omitempty"`
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

// runMemResidueChild runs TestMemResidueHelperProcess in the given mode and
// returns its report.
func runMemResidueChild(t *testing.T, mode string) memResidueReport {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMemResidueHelperProcess$", "-test.count=1") // #nosec G204 -- os.Args[0] is this test binary
	cmd.Env = append(os.Environ(), envMemResidueHelper+"="+t.TempDir(), envMemResidueMode+"="+mode)
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() { out, runErr = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("memory-residue child (%s) exceeded 2m", mode)
	}
	var rep memResidueReport
	found := false
	for line := range strings.SplitSeq(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, memResidueMarker); ok {
			if err := json.Unmarshal([]byte(rest), &rep); err != nil {
				t.Fatalf("bad child report %q: %v", rest, err)
			}
			found = true
		}
	}
	if !found || runErr != nil || rep.Error != "" || rep.Mode != mode {
		t.Fatalf("child (%s) failed: err=%v report-error=%q found=%v mode=%q output:\n%.2000s", mode, runErr, rep.Error, found, rep.Mode, out)
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
		rep := runMemResidueChild(t, memResidueModeRed)
		for _, f := range memResidueRedVerdict(rep) {
			t.Error(f)
		}
		t.Logf("red control: dek hits %d live, %d after zeroing the claimed copy", countHits(rep.LiveHits, func(h memHit) bool { return h.Name == "dek" }), countHits(rep.AfterHits, func(h memHit) bool { return h.Name == "dek" }))
	})

	t.Run("after-shutdown", func(t *testing.T) {
		rep := runMemResidueChild(t, memResidueModeMeasure)
		t.Logf("scanned %d bytes live, %d after Shutdown; live hits %d, after hits %d", rep.ScannedLive, rep.ScannedPost, len(rep.LiveHits), len(rep.AfterHits))
		failures, notes := memResidueVerdict(rep, memResidueRatchet)
		for _, n := range notes {
			t.Log(n)
		}
		for _, f := range failures {
			t.Error(f)
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
	rep := memResidueReport{Mode: os.Getenv(envMemResidueMode)}
	fail := func(format string, a ...any) {
		rep.Error = fmt.Sprintf(format, a...)
		emitMemResidue(rep)
	}
	if rep.Mode != memResidueModeMeasure && rep.Mode != memResidueModeRed {
		fail("unknown mode %q", rep.Mode)
		return
	}
	svc, needles, claims, err := startMemResidueService(dir)
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

// startMemResidueService runs the lifecycle under test up to the live scan: a
// random KEK in a "file" key-provider file, a first-boot Initialize. It returns
// the needles (masked; the plain key bytes it read are wiped) and the claimed
// copies' addresses.
func startMemResidueService(dir string) (*Service, []memNeedle, []memResidueClaim, error) {
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, nil, nil, fmt.Errorf("rand: %w", err)
	}
	kekPath := filepath.Join(dir, "kek.bin")
	if err := os.WriteFile(kekPath, kek, 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write kek: %w", err)
	}
	needles := []memNeedle{newMemNeedle("kek", kek)}
	wipeBytes(kek)

	cfg := &config.EncryptionConfig{
		Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: kekPath},
	}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(""); err != nil {
		return nil, nil, nil, fmt.Errorf("initialize: %w", err)
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

func emitMemResidue(rep memResidueReport) {
	b, _ := json.Marshal(rep)
	fmt.Println(memResidueMarker + string(b))
}
