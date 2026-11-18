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

// TestResguardSSH_RedGreen proves the budget is neither vacuous nor a false
// positive: a benign cost passes (GREEN), a 1 GiB alloc spike trips it (RED).
func TestResguardSSH_RedGreen(t *testing.T) {
	b := resguard.Calibrate("ssh_test", rgBenignCosts(t), resguard.DefaultFactor)
	delete(b.Meters, "live_heap")
	benign := rgBenignCosts(t)[0]
	var benignFired bool
	b.Check(func(string, ...any) { benignFired = true }, benign)
	if benignFired {
		t.Fatal("GREEN failed: benign cost tripped the budget")
	}
	red := benign
	red.AllocBytes = benign.AllocBytes*1000 + (1 << 30)
	red.Mallocs = benign.Mallocs*1000 + (1 << 20)
	red.AllocSampled = true
	var redFired bool
	b.Check(func(string, ...any) { redFired = true }, red)
	if !redFired {
		t.Fatal("RED failed: a 1 GiB alloc spike did not trip the budget")
	}
}
