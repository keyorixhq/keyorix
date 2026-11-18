package azurefuzz

// resguard_azure_test.go — PK1 port of the Azure Key Vault connector fuzz target
// (FuzzAzureGetSecret) onto the shared resguard resource layer. This is a CONNECTOR
// target, so per the brief it gets the network meter in addition to memory/CPU:
//
//   - NetMeter (air-gap + byte volume): httpClient()'s dial is routed through the
//     package-global air-gapped azureNet, so any non-loopback dial a regression
//     introduced fails the air-gap oracle, and response/request bytes are metered.
//   - memory/CPU: alloc_bytes/mallocs (RAM-spike signal) + cpu_ns (advisory).
//
// Existing canary/echo/no-panic/no-hang oracles (checkOracles) are UNCHANGED.
//
// Sleep is NOT metered here: this target's azcore retry is configured with a
// positive, bounded RetryDelay (1–2 ms, see newVaultClient), so the azcore
// RetryDelay<=0 → 60 s backoff bug (already demonstrated live by RSG2's connect
// pilot, TestResguardAzureSleepRedGreen) is NOT reachable through this config. The
// bounded-retry structural oracle + the 6 s context + the 20 s watchdog bound the
// real sleep. Wiring the azcore log-listener here would add a seam with nothing to
// catch — stated, not silently dropped.
//
// What this oracle does NOT verify: correctness; alloc is sampled; CPU is
// process-wide advisory; NetMeter counts CIPHERTEXT bytes under TLS (a size signal,
// not plaintext) and only dials routed through httpClient()'s DialContext; alloc
// cannot be separated between the live TLS server, the azsecrets client and the
// decoder (all inside the measured call).

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// azureNet is the package-global air-gapped NetMeter wired into httpClient(). One
// global is correct: the stock fuzz engine runs one body at a time per process and
// the Probe resets the meter before each input; -parallel forks processes.
var azureNet = resguard.NewNetMeter()

const azureBudgetPath = "testdata/resguard-azure-getsecret.json"

func azureResguardProbe(f *testing.F) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32, Net: azureNet})
	b, err := resguard.LoadBudget(azureBudgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", azureBudgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

// azureConnMeters: keep alloc/CPU + the network byte volume for this connector.
// live_heap dropped (whole-process). dials/net always checked (air-gap independent).
var azureConnMeters = []string{"alloc_bytes", "mallocs", "cpu_ns", "net_bytes_in", "net_bytes_out"}

var azureSecretBody = []byte(`{"value":"s3cr3t","id":"https://v.vault.azure.net/secrets/db/abc123"}`)

func azureBenignInputs() [][]byte {
	return [][]byte{
		encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, body: azureSecretBody}}),
		encodeSeeds([]seedSpec{{status: 404, ctSel: ctJSON, body: []byte(`{"error":{"code":"SecretNotFound"}}`)}}),
		encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, body: []byte(`{"value":""}`)}}),
		encodeSeeds([]seedSpec{{status: 500, ctSel: ctJSON, body: []byte(``)}}), // retriable
	}
}

// azureDriveMeasured drives one benign input through the real GetSecret path under
// the probe (used only by calibration/red-green; the fuzz body is inline so it can
// also run checkOracles). Returns the zero Cost if the input would skip.
func azureDriveMeasured(t *testing.T, probe *resguard.Probe, data []byte) resguard.Cost {
	t.Helper()
	specs := decodeSpecs(data)
	fs, err := newFakeServer(specs)
	if err != nil {
		return resguard.Cost{}
	}
	defer fs.Close()
	cl, err := newVaultClient(fs.url())
	if err != nil {
		return resguard.Cost{}
	}
	return probe.Measure(len(data), func() {
		_, _, _ = runWithWatchdog(t, "GetSecret", func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			return callGetSecret(cl, ctx)
		})
	})
}

func calibrateAzureConn(t testing.TB) resguard.Budget {
	t.Helper()
	tt := t.(*testing.T)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: azureNet})
	var costs []resguard.Cost
	for range 3 {
		for _, data := range azureBenignInputs() {
			costs = append(costs, azureDriveMeasured(tt, probe, data))
		}
	}
	b := resguard.Calibrate("azure_getsecret", costs, resguard.DefaultFactor)
	b.KeepOnly(azureConnMeters...)
	return b
}

func TestResguardAzureConnCalibrate(t *testing.T) {
	b := calibrateAzureConn(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no meter calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(azureBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", azureBudgetPath, b.Summary())
	}
}

// TestResguardAzureConnRedGreen — committed red/green for the connector memory
// oracle, plus a live assertion that the benign path makes ZERO non-loopback dials
// (the air-gap oracle is green on a benign input and would go red on an out-dial).
func TestResguardAzureConnRedGreen(t *testing.T) {
	b := calibrateAzureConn(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: azureNet})
	green := azureDriveMeasured(t, probe, azureBenignInputs()[0])
	if green.NonLoopbackDials != 0 {
		t.Fatalf("benign GetSecret must make no non-loopback dial, got %d", green.NonLoopbackDials)
	}
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign GetSecret (alloc=%d, net_in=%d) must pass the budget", green.AllocBytes, green.NetBytesIn)
	}
	red := green
	red.Sampled = true
	red.AllocBytes = green.AllocBytes*1000 + 1<<30
	red.Mallocs = green.Mallocs*1000 + 1
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("RED: a 1000x alloc amplification must trip the budget")
	}
	if !strings.Contains(msg, "alloc_bytes") {
		t.Fatalf("RED: failure message should name alloc_bytes: %q", msg)
	}
	t.Logf("GREEN alloc=%d net_in=%d net_out=%d passes; RED alloc=%d fires: %s",
		green.AllocBytes, green.NetBytesIn, green.NetBytesOut, red.AllocBytes, msg)
}
