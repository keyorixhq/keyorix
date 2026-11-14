package libconformance

// FuzzPKCS7TimeTravelOracle is the mutation layer of the TT1 time-travel
// differential (scripts/fuzzing/time-travel/). It coverage-fuzzes the
// REPO-PINNED digitorus/pkcs7 (the "new" version, compiled into this test
// binary, so Go's fuzzer sees its coverage) while an OLDER version of the same
// library runs as a long-lived subprocess ORACLE. Two versions of one import
// path cannot link into one binary, which is exactly why the oracle crosses a
// process boundary: the subprocess is the single-version driver at
// scripts/fuzzing/time-travel/drivers/pkcs7, built against a historical version
// by run.sh and passed in via TT1_PKCS7_OLD_DRIVER.
//
// Oracle policy (security-oriented, not "any divergence fails"):
//
//   - FAIL if NEW accepts an input the OLD version REJECTED. New-more-lenient is
//     the dangerous direction: a structure an older, battle-tested parser
//     refused is now accepted — the shape a signature/verification bypass would
//     take. This is the load-bearing assertion.
//   - FAIL if NEW panics. A new crash is a robustness regression.
//   - ALLOW (expected, logged) the reverse: NEW stricter (new rejects what old
//     accepted — a hardening), NEW bounding work where OLD did not (the
//     maximum-nesting-depth / amplification fix, where OLD may even crash), and
//     both-reject-with-different-wording.
//
// What this oracle does NOT verify (stated so the green is not oversold):
//   - It does NOT compare allocation/time between versions — the fuzzer shares
//     one heap with the in-process new parser, so an alloc delta here is noise.
//     Bounded-work across versions is measured by the OUT-OF-PROCESS differential
//     runner (run.sh + compare.go), where each version has its own address space.
//   - It does NOT prove the OLD version is a correct ground truth; it only pins
//     the DIRECTION of change. An input both versions get wrong agrees and passes.
//   - It only drives pkcs7.Parse (the BER→DER + structural decode surface
//     Keyorix reaches via notary.VerifyReceipt); it does not exercise Verify,
//     Decrypt, or signing.
//   - Without TT1_PKCS7_OLD_DRIVER set it degrades to a never-panic invariant on
//     the new version only (so plain `go test` stays green); the differential
//     assertions require the env and are what the TT1 fuzz campaign runs.
import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// ttClassify mirrors the driver's error bucketing so the in-process new-version
// result is comparable to the subprocess old-version result. Kept byte-identical
// in spirit to scripts/fuzzing/time-travel/drivers/pkcs7/main.go: classify.
func ttClassify(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case msg == "":
		return "none"
	case strings.Contains(m, "ber2der") || strings.Contains(m, "indefinite") || strings.Contains(m, "ber "):
		return "ber"
	case strings.Contains(m, "invalid length") || strings.Contains(m, "length") || strings.Contains(m, "truncat") || strings.Contains(m, "out of bound") || strings.Contains(m, "index out of range"):
		return "length"
	case strings.Contains(m, "trailing"):
		return "trailing"
	case strings.Contains(m, "asn1") || strings.Contains(m, "unmarshal") || strings.Contains(m, "sequence") || strings.Contains(m, "tag") || strings.Contains(m, "integer"):
		return "asn1"
	case strings.Contains(m, "unsupported") || strings.Contains(m, "not supported") || strings.Contains(m, "unknown"):
		return "unsupported"
	case strings.Contains(m, "nil") || strings.Contains(m, "pointer"):
		return "nil"
	default:
		return "other"
	}
}

type ttResult struct {
	Verdict  string `json:"verdict"` // accept | reject | panic | crash
	ErrClass string `json:"errclass"`
	ErrRaw   string `json:"errraw"`
}

// newParse runs the repo-pinned (new) pkcs7.Parse in-process and classifies it
// exactly as the driver does. A panic is reported as verdict "panic".
func newParse(data []byte) (res ttResult) {
	defer func() {
		if r := recover(); r != nil {
			res.Verdict = "panic"
			res.ErrRaw = strings.TrimSpace(strings.SplitN(fmtSprint(r), "\n", 2)[0])
			res.ErrClass = ttClassify(res.ErrRaw)
		}
	}()
	_, err := pkcs7.Parse(data)
	if err != nil {
		return ttResult{Verdict: "reject", ErrRaw: err.Error(), ErrClass: ttClassify(err.Error())}
	}
	return ttResult{Verdict: "accept", ErrClass: "none"}
}

func fmtSprint(v any) string {
	if e, ok := v.(error); ok {
		return e.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "panic"
}

// oldOracle wraps the long-lived single-version subprocess. Access is serialized
// because Go fuzzing drives the fuzz function from multiple goroutines.
type oldOracle struct {
	mu   sync.Mutex
	path string
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Scanner
}

func startOracle(path string) (*oldOracle, error) {
	o := &oldOracle{path: path}
	if err := o.spawn(); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *oldOracle) spawn() error {
	cmd := exec.Command(o.path)
	cmd.Stderr = io.Discard
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	o.cmd, o.in, o.out = cmd, in, sc
	return nil
}

// ask sends one input to the old driver and returns its classified result. On a
// broken pipe (the old version crashed — e.g. unbounded recursion on deep
// nesting), it reports verdict "crash" and respawns for the next input.
func (o *oldOracle) ask(data []byte) ttResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	line := "x\t" + hex.EncodeToString(data) + "\n"
	if _, err := io.WriteString(o.in, line); err != nil {
		_ = o.cmd.Process.Kill()
		_ = o.spawn()
		return ttResult{Verdict: "crash", ErrClass: "crash"}
	}
	if !o.out.Scan() {
		_ = o.cmd.Process.Kill()
		_ = o.spawn()
		return ttResult{Verdict: "crash", ErrClass: "crash"}
	}
	var r struct {
		Verdict  string `json:"verdict"`
		ErrClass string `json:"errclass"`
		ErrRaw   string `json:"errraw"`
	}
	if json.Unmarshal(o.out.Bytes(), &r) != nil {
		return ttResult{Verdict: "crash", ErrClass: "crash"}
	}
	return ttResult{Verdict: r.Verdict, ErrClass: r.ErrClass, ErrRaw: r.ErrRaw}
}

var (
	oracleOnce sync.Once
	oracleInst *oldOracle
	oracleErr  error
)

func getOracle() (*oldOracle, error) {
	oracleOnce.Do(func() {
		path := os.Getenv("TT1_PKCS7_OLD_DRIVER")
		if path == "" {
			return
		}
		oracleInst, oracleErr = startOracle(path)
	})
	return oracleInst, oracleErr
}

func FuzzPKCS7TimeTravelOracle(f *testing.F) {
	// Seeds: the committed pkcs7 fuzz seeds plus a nesting vector that straddles
	// the depth cap, so the differential starts right at the known boundary.
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))
	f.Add([]byte{})
	f.Add(nestIndef(501))
	f.Add(nestIndef(100))

	oracle, err := getOracle()
	if err != nil {
		f.Fatalf("TT1_PKCS7_OLD_DRIVER set but oracle failed to start: %v", err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var nw ttResult
		fuzzutil.Guard(t.Fatalf, "pkcs7.Parse(new)", func() { nw = newParse(data) })

		// Standalone invariant (always on): the new parser must never panic.
		if nw.Verdict == "panic" {
			t.Fatalf("NEW pkcs7.Parse panicked: %q (input %x)", nw.ErrRaw, data)
		}
		if oracle == nil {
			return // differential disabled without the env; new-never-panic still checked.
		}

		old := oracle.ask(data)

		// Load-bearing assertion: NEW must not ACCEPT what OLD REJECTED.
		if nw.Verdict == "accept" && old.Verdict == "reject" {
			t.Fatalf("DIVERGENCE (new-more-lenient): new=accept old=reject old-err=%q input=%x",
				old.ErrRaw, data)
		}
		// Expected/known directions are allow-listed and merely logged.
		switch {
		case nw.Verdict == old.Verdict && nw.ErrClass == old.ErrClass:
			// agreement, nothing to record.
		case old.Verdict == "crash":
			t.Logf("EXPECTED old-crash (bounded-work fix): new=%s input-len=%d", nw.Verdict, len(data))
		case nw.Verdict == "reject" && old.Verdict == "accept":
			t.Logf("EXPECTED hardening (new stricter): new-err=%q input-len=%d", nw.ErrRaw, len(data))
		case strings.Contains(nw.ErrRaw, "maximum nesting depth"):
			t.Logf("EXPECTED depth-cap: input-len=%d", len(data))
		default:
			t.Logf("divergence(other): new=%s/%s old=%s/%s input-len=%d",
				nw.Verdict, nw.ErrClass, old.Verdict, old.ErrClass, len(data))
		}
	})
}

func nestIndef(d int) []byte {
	var b []byte
	for i := 0; i < d; i++ {
		b = append(b, 0x30, 0x80)
	}
	b = append(b, 0x05, 0x00)
	for i := 0; i < d; i++ {
		b = append(b, 0x00, 0x00)
	}
	return b
}
