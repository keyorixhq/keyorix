//go:build !noazure

package connect

// resguard_azure_pilot_test.go — calibration + the committed red/green proof for
// RSG2 Pilot #2's SleepClock oracle (see resguard_azure_pilot_fuzz_test.go).

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// azureCalibrationSeeds are benign (status, body) pairs covering the no-retry and
// the retriable paths, so the calibrated sleep_ns ceiling reflects real backoff.
var azureCalibrationSeeds = []struct {
	status int
	body   []byte
}{
	{200, []byte(`{"value":"s3cr3t"}`)},
	{404, []byte(`{"error":{"code":"SecretNotFound"}}`)},
	{500, []byte(``)},          // retriable -> two 1 ms backoffs
	{503, []byte(`slow down`)}, // retriable
	{429, []byte(``)},          // retriable
}

// measureAzureGet drives one real GetSecret against a fresh fake server with the
// given retry options and returns the metered Cost. ctxTimeout bounds the real
// time.After so a pathological intended backoff does not actually block.
func measureAzureGet(t testing.TB, probe *resguard.Probe, nm *resguard.NetMeter, status int, body []byte, retry policy.RetryOptions, ctxTimeout time.Duration) resguard.Cost {
	t.Helper()
	var hits, challengeHits int32
	srv := azureFakeKV(clampHTTPStatus(status), body, &hits, &challengeHits)
	defer srv.Close()
	cl := azureMeteredClient(t, srv, nm, retry)
	c := NewAzureKeyVaultConnector("fuzz", srv.URL, nil)
	c.newClient = func(_ context.Context) (azSecretGetter, error) { return cl, nil }

	return probe.Measure(len(body), func() {
		ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
		defer cancel()
		_, _ = c.GetSecret(ctx, "fuzz-secret")
	})
}

// calibrateAzure derives the Pilot #2 budget from the benign seeds under the
// correct retry config. sleep_ns is judged in ModeAbsolute: the legitimate backoff
// is bounded by the retry CONFIG, not by input size, so an input-size-independent
// ceiling is the right model (and it exercises RSG2's AbsMax).
func calibrateAzure(t testing.TB) resguard.Budget {
	t.Helper()
	installAzureRetryDelayListener()
	nm := resguard.NewNetMeter()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: nm, Clock: azureSleepClock})
	retry := policy.RetryOptions{MaxRetries: 2, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond}

	var costs []resguard.Cost
	for range 4 { // repeat to average scheduling noise into p99
		for _, s := range azureCalibrationSeeds {
			costs = append(costs, measureAzureGet(t, probe, nm, s.status, s.body, retry, 2*time.Second))
		}
	}
	b := resguard.Calibrate("azure_connector_response", costs, resguard.DefaultFactor)
	// Keep only the per-input-attributable meters. This target drives a live
	// httptest TLS server + a real azsecrets client, so the process-global memory
	// meters (alloc_bytes/mallocs/live_heap, a whole-process ReadMemStats+GC) are
	// noisy and NOT a single input's fault (a 1.4× live_heap fluctuation is GC
	// timing, not an amplification; a real leak is Drift's job, not Budget's).
	// sleep_ns is the Azure-bug oracle; net_bytes_in/out are the response/request
	// size signals from NetMeter. Air-gap (NonLoopbackDials) is checked
	// independently of this set.
	b.KeepOnly("sleep_ns", "net_bytes_in", "net_bytes_out")
	b.UseAbsolute("sleep_ns") // backoff is config-bounded, input-size-independent
	return b
}

// TestResguardAzureCalibrate regenerates the committed budget when
// RESGUARD_CALIBRATE=1; otherwise it asserts a sleep_ns budget was produced.
func TestResguardAzureCalibrate(t *testing.T) {
	b := calibrateAzure(t)
	if _, ok := b.Meters["sleep_ns"]; !ok {
		t.Fatalf("sleep_ns should be calibrated (retriable seeds must have slept); %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(azurePilotBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", azurePilotBudgetPath, b.Summary())
	}
}

// TestResguardAzureSleepRedGreen is the committed red/green proof for the
// SleepClock oracle against the Azure SDK retry-delay defect.
//
// GREEN: the correct config (RetryDelay 1 ms) retrying a 500 meters only a few ms
// of backoff — under the calibrated ceiling.
//
// RED: RetryDelay -1 — the SDK's own documented way to ask for "no delay" — is
// normalized to 0 by setDefaults and then MISCLASSIFIED as overflow by calcDelay
// (0 < factor), so the policy intends a ~MaxRetryDelay (60 s) backoff on the very
// first retry. The SleepClock meters that ~60 s via the log seam while a 500 ms
// context deadline keeps the REAL sleep sub-second — so the oracle fires on an
// unbounded backoff that a wall-clock test under the same deadline would miss
// entirely. This is a vendored-SDK behaviour (THIRD-PARTY), reproduced to prove
// the oracle catches the class; no Keyorix production code is involved.
func TestResguardAzureSleepRedGreen(t *testing.T) {
	b := calibrateAzure(t)
	if _, ok := b.Meters["sleep_ns"]; !ok {
		t.Fatalf("no sleep_ns budget calibrated")
	}
	installAzureRetryDelayListener()
	nm := resguard.NewNetMeter()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: nm, Clock: azureSleepClock})

	// GREEN: correct config, retriable 500 -> a couple of ms metered.
	green := measureAzureGet(t, probe, nm, 500, []byte(``),
		policy.RetryOptions{MaxRetries: 2, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond},
		2*time.Second)
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: correct-config backoff (%s metered) must pass the budget", green.Sleep)
	}

	// RED: RetryDelay -1 -> ~60 s intended backoff, metered but not slept.
	redStart := time.Now()
	red := measureAzureGet(t, probe, nm, 500, []byte(``),
		policy.RetryOptions{MaxRetries: 2, RetryDelay: -1, MaxRetryDelay: 60 * time.Second},
		500*time.Millisecond)
	wall := time.Since(redStart)
	if red.Sleep < 10*time.Second {
		t.Fatalf("RED: RetryDelay -1 should meter a ~60 s intended backoff, got %s metered", red.Sleep)
	}
	if wall > 5*time.Second {
		t.Fatalf("RED: the real sleep must be aborted by the context deadline (wall %s), proving the oracle sees what the wall clock cannot", wall)
	}
	var redMsg string
	fired := b.Check(func(f string, a ...any) { redMsg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("RED: metered backoff %s must trip the budget", red.Sleep)
	}
	if !strings.Contains(redMsg, "sleep_ns") {
		t.Fatalf("RED: failure message should name sleep_ns: %q", redMsg)
	}
	t.Logf("GREEN backoff=%s passes; RED backoff=%s (wall %s, real sleep aborted) fires: %s",
		green.Sleep, red.Sleep, wall, redMsg)
}
