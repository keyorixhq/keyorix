package sshhostile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// rgBudgetPath is the committed resguard budget for FuzzSSHParseAuthorizedKey.
// Regenerate with: RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/ssh -run TestResguardSSHCalibrate
const rgBudgetPath = "testdata/resguard-ssh.json"

// rgBenignCosts measures ssh.ParseAuthorizedKey over benign seeds (a valid
// ed25519 line, a freshly generated ECDSA line, truncated keys, a comment line,
// empty input) for calibration.
func rgBenignCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&ek.PublicKey)
	if err != nil {
		tb.Fatalf("ssh pubkey: %v", err)
	}
	seeds := [][]byte{
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCNPj70vRk7BvDxM2cSOWZ0f1ayczW+5stLTUgYD7D5 admin@keyorix"),
		ssh.MarshalAuthorizedKey(pub),
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 comment"),
		[]byte("ssh-rsa AAAAB3NzaC1yc2E"),
		[]byte(""),
		[]byte("# just a comment line\n"),
	}
	var costs []resguard.Cost
	for range 4 {
		for _, data := range seeds {
			probe := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, probe.Measure(len(data), func() { _, _, _, _, _ = ssh.ParseAuthorizedKey(data) }))
		}
	}
	return costs
}

// TestResguardSSHCalibrate regenerates the committed budget under RESGUARD_CALIBRATE=1.
func TestResguardSSHCalibrate(t *testing.T) {
	b := resguard.Calibrate("ssh_authorizedkey", rgBenignCosts(t), resguard.DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%s", b.Summary())
	}
	// live_heap is a whole-process post-GC reading dominated by the fuzz engine's
	// own heap, not attributable to one input; alloc_bytes/mallocs stay fatal.
	delete(b.Meters, "live_heap")
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardSSH_RedGreen proves the COMMITTED budget (rgBudgetPath, the file
// the fuzz target loads) is armed and is neither vacuous nor a false positive:
// every benign cost passes it (GREEN) and a 1 GiB alloc spike trips it (RED).
func TestResguardSSH_RedGreen(t *testing.T) {
	b := rgLoadBudget(t)
	benign := rgBenignCosts(t)
	for i, c := range benign {
		var fired bool
		b.Check(func(string, ...any) { fired = true }, c)
		if fired {
			t.Fatalf("GREEN failed: benign cost #%d (%d bytes) tripped the committed budget: %s", i, c.InputLen, b.Summary())
		}
	}
	red := benign[0]
	red.AllocBytes = red.AllocBytes*1000 + (1 << 30)
	red.Mallocs = red.Mallocs*1000 + (1 << 20)
	red.AllocSampled = true
	var redFired bool
	b.Check(func(string, ...any) { redFired = true }, red)
	if !redFired {
		t.Fatal("RED failed: a 1 GiB alloc spike did not trip the committed budget")
	}
}

// rgLoadBudget loads the committed budget and fails closed: a missing,
// unparsable or zero-factor file, or one that does not arm the fatal
// alloc_bytes/mallocs meters, fails the caller instead of silently turning the
// resource oracle off.
func rgLoadBudget(tb testing.TB) resguard.Budget {
	tb.Helper()
	b, err := resguard.LoadBudget(rgBudgetPath)
	if err != nil {
		tb.Fatalf("no usable committed budget at %s (regenerate with RESGUARD_CALIBRATE=1 go test -run TestResguardSSHCalibrate): %v", rgBudgetPath, err)
	}
	for _, m := range []string{"alloc_bytes", "mallocs"} {
		if mb, ok := b.Meters[m]; !ok || mb.Floor <= 0 {
			tb.Fatalf("committed budget %s does not arm the fatal meter %s: %s", rgBudgetPath, m, b.Summary())
		}
	}
	return b
}
