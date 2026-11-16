package osairgap

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// sysProcNetns is the SysProcAttr for a bare net-namespace child (used by the
// quick capability check in requireNetns).
var sysProcNetns = syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}

// Helper roles for the re-exec'd child. The parent sets AGP1_OSAIRGAP_ROLE; this
// TestMain dispatches BEFORE any test runs, so the child never runs the suite.
const (
	rolePhoneHome = "phonehome"
	roleBenign    = "benign"
)

func TestMain(m *testing.M) {
	switch os.Getenv(envRole) {
	case roleNS:
		RunNSInit() // inside the netns; exits
	case rolePhoneHome:
		runPhoneHome() // exits
	case roleBenign:
		runBenign() // exits
	}
	os.Exit(m.Run())
}

// TestOsairgapNSInitDispatch exists only so Run()'s -test.run selector names a
// real test; TestMain actually intercepts the nsinit role before this runs.
func TestOsairgapNSInitDispatch(t *testing.T) {
	if IsNSInit() {
		RunNSInit()
	}
	t.Skip("dispatch shim; real work happens in TestMain for the nsinit child")
}

// runPhoneHome stands in for a HYPOTHETICAL Keyorix that tries to egress. It is
// the RED side of the OS-level oracle's red/green proof: a target that phones
// home must be caught. It does two distinct egress attempts:
//   - an HTTP GET to a non-loopback host, which honours HTTP_PROXY → lands on the
//     loopback canary (deterministic CanaryHit with target);
//   - a direct TCP dial to a non-loopback host, which the netns blocks with
//     ENETUNREACH (containment) and which may show as a SYN_SENT /proc peer.
// No production code is touched — the "defect" is this test-only helper.
func runPhoneHome() {
	// Proxy-respecting HTTP egress → canary.
	cl := &http.Client{Timeout: 3 * time.Second}
	if resp, err := cl.Get("http://malicious.example.net/beacon"); err == nil {
		resp.Body.Close()
	}
	// Direct non-loopback dial → containment (ENETUNREACH) + maybe /proc.
	d := net.Dialer{Timeout: 3 * time.Second}
	if c, err := d.Dial("tcp", "10.255.255.1:443"); err == nil {
		c.Close()
	} else {
		fmt.Fprintf(os.Stderr, "phonehome direct dial blocked: %v\n", err)
	}
	os.Exit(0)
}

// runBenign is the GREEN side: a target that only ever touches loopback. The
// oracle must NOT fire. It binds a loopback listener and dials it, nothing else.
func runBenign() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "benign listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benign dial: %v\n", err)
		os.Exit(1)
	}
	c.Close()
	os.Exit(0)
}

// oracle runs the Allowlist over a Result and returns the list of egress
// violations (canary hits are always violations — an egress INTENT; proc peers
// are violations unless classified allowed).
func (a Allowlist) violations(r *Result) []string {
	var v []string
	for _, h := range r.CanaryHits {
		v = append(v, "canary egress intent: "+h)
	}
	for _, p := range r.ProcPeers {
		if ok, _ := a.Classify(p); !ok {
			v = append(v, "direct egress to "+p.String())
		}
	}
	return v
}

func requireNetns(t *testing.T) {
	t.Helper()
	// A quick check that we can create a net namespace at all.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.SysProcAttr = &sysProcNetns
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot create network namespace (CLONE_NEWNET): %v", err)
	}
}

// TestAirgap_PhoneHome_OracleFires is the RED proof: a phone-home target is
// caught by the OS-level oracle (canary hit and/or containment error).
func TestAirgap_PhoneHome_OracleFires(t *testing.T) {
	requireNetns(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, os.Args[0], RunSpec{
		Argv:    []string{os.Args[0], "-test.run=^$"},
		Env:     []string{envRole + "=" + rolePhoneHome},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("result: lo_up=%v canary=%s hits=%v procPeers=%v samples=%d stderrTail=%q",
		res.LoUp, res.CanaryAddr, res.CanaryHits, res.ProcPeers, res.ProcSamples, res.TargetStderrTail)
	v := Allowlist{}.violations(res)
	if len(v) == 0 {
		t.Fatalf("RED proof failed: phone-home target produced NO egress signal; canary/proc both empty — the oracle is blind")
	}
	// Specifically, the proxy-respecting GET must have reached the canary.
	if len(res.CanaryHits) == 0 {
		t.Errorf("expected a canary hit from the proxy-respecting GET; got none (containment may still have fired: %v)", v)
	}
	// And the direct dial must have been contained (ENETUNREACH in stderr).
	if !strings.Contains(res.TargetStderrTail, "unreachable") && !strings.Contains(res.TargetStderrTail, "blocked") {
		t.Logf("note: direct-dial containment error not visible in stderr tail (%q)", res.TargetStderrTail)
	}
}

// TestAirgap_Benign_NoEgress is the GREEN proof: a loopback-only target produces
// zero egress signal, so the oracle does not false-fire.
func TestAirgap_Benign_NoEgress(t *testing.T) {
	requireNetns(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, os.Args[0], RunSpec{
		Argv:    []string{os.Args[0], "-test.run=^$"},
		Env:     []string{envRole + "=" + roleBenign},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("result: lo_up=%v exit=%d canary=%s hits=%v procPeers=%v samples=%d",
		res.LoUp, res.TargetExit, res.CanaryAddr, res.CanaryHits, res.ProcPeers, res.ProcSamples)
	if !res.LoUp {
		t.Fatalf("loopback was not brought up in the netns (init err=%q): benign target cannot run", res.InitErr)
	}
	if res.TargetExit != 0 {
		t.Fatalf("benign target exited %d: stderr=%q", res.TargetExit, res.TargetStderrTail)
	}
	if v := (Allowlist{}).violations(res); len(v) != 0 {
		t.Fatalf("GREEN proof failed: benign loopback-only target flagged as egress: %v", v)
	}
}

// TestOsairgapImportedOnlyFromTests: no non-test .go file may import this
// test-only package (mirrors INV-RES-test-only for resguard).
func TestOsairgapImportedOnlyFromTests(t *testing.T) {
	root := repoRootOrSkip(t)
	const importPath = `"github.com/keyorixhq/keyorix/internal/fuzzutil/osairgap"`
	var offenders []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, e := os.ReadFile(p) // #nosec G304 -- walking this repo's own tree
		if e != nil {
			return nil
		}
		if strings.Contains(string(b), importPath) {
			rel, _ := filepath.Rel(root, p)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if len(offenders) > 0 {
		t.Fatalf("osairgap is test-only but imported by non-test file(s): %s", strings.Join(offenders, ", "))
	}
}

func repoRootOrSkip(t *testing.T) string {
	t.Helper()
	var root string
	func() {
		defer func() {
			if recover() != nil {
				root = ""
			}
		}()
		root = srcpath.RepoRoot()
	}()
	if root == "" {
		t.Skip("repo root not resolvable (binary run away from checkout)")
	}
	return root
}
