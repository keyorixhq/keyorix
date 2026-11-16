//go:build !noazure

package connect

// resguard_azure_pilot_fuzz_test.go — RSG2 Pilot #2.
//
// This wires two resguard oracles into the Azure Key Vault connector response
// target against the exact bug class that motivated them:
//
//   - SleepClock (virtual time) — the Azure SDK retry-delay defect. The azcore
//     retry policy sleeps via a bare time.After(delay) (azcore runtime
//     policy_retry.go:214) with NO injectable clock seam, so SleepClock cannot be
//     spliced into the real sleep. It CAN meter the delay the policy INTENDS: the
//     policy logs "End Try #N, Delay=%v" (line 212) immediately BEFORE sleeping,
//     and azcore exposes log.SetListener. We route that line into a SleepClock.
//     A short per-call context deadline aborts the real time.After, so a RetryDelay
//     that normalizes to a 60 s backoff is METERED at ~60 s while wall time stays
//     sub-second. This is precisely the signal a wall-clock oracle under a deadline
//     CANNOT see (the deadline hides the intended sleep), which is the whole point.
//   - NetMeter (air-gap + byte volume) — the connector must only ever dial its
//     configured loopback endpoint. The client's dial is routed through
//     NetMeter.DialContext (which also trusts the httptest TLS cert), so any
//     non-loopback dial a regression introduced would fail the air-gap oracle, and
//     the response byte volume is metered. (Bytes are counted at the TCP conn, so
//     under TLS they are CIPHERTEXT bytes — a response-SIZE signal, not plaintext.)
//
// What this pilot does NOT verify: SleepClock sees only the delay the SDK LOGS (a future SDK that sleeps
// without logging the delay is invisible to it; the context deadline + the
// wall-clock Guard are the backstop); NetMeter sees only dials routed through its
// DialContext, counts ciphertext under TLS, and treats a hostname needing DNS as
// non-loopback. No production code is modified.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// azureSleepClock is the process-global clock the azcore retry-policy log listener
// feeds. The stock fuzz engine runs one body at a time per process, and the
// azsecrets retry policy logs its intended delay synchronously on the calling
// goroutine immediately BEFORE it sleeps, so one global clock reset per input (by
// the Probe) is correct. -parallel forks processes, each with its own copy.
var azureSleepClock = resguard.NewSleepClock()

var installAzureRetryLogOnce sync.Once

// installAzureRetryDelayListener routes every azcore retry-policy "Delay=%v" log
// line into azureSleepClock — the only seam into the SDK's backoff. SetEvents/
// SetListener are documented as "call before using SDK clients", so this runs once
// before any client is built.
func installAzureRetryDelayListener() {
	installAzureRetryLogOnce.Do(func() {
		azlog.SetEvents(azlog.EventRetryPolicy)
		azlog.SetListener(func(e azlog.Event, msg string) {
			if e != azlog.EventRetryPolicy {
				return
			}
			_, after, found := strings.Cut(msg, "Delay=")
			if !found { // only the pre-sleep "End Try #N, Delay=%v" line carries it
				return
			}
			d, err := time.ParseDuration(strings.TrimSpace(after))
			if err != nil {
				return
			}
			azureSleepClock.Sleep(d)
		})
	})
}

// azureFakeKV builds the challenge-handshake fake Key Vault server used by both the
// fuzz target and the red/green test, serving the given status/body on the
// authenticated request. hits counts authenticated responses (the retry-bound
// oracle). Mirrors azurekv_response_fuzz_test.go's server exactly.
func azureFakeKV(code int, body []byte, hits, challengeHits *int32) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			atomic.AddInt32(challengeHits, 1)
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://fake.local/tenant" resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(hits, 1)
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
}

// azureMeteredClient builds a real azsecrets.Client whose HTTP dial is routed
// through nm (air-gap + byte metering) while still trusting srv's self-signed TLS
// cert, with the production refuseRedirect installed and the given retry options.
func azureMeteredClient(t testing.TB, srv *httptest.Server, nm *resguard.NetMeter, retry policy.RetryOptions) *azsecrets.Client {
	t.Helper()
	base, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httptest TLS client Transport is not *http.Transport")
	}
	tr := &http.Transport{
		DialContext:       nm.DialContext, // metered + air-gapped; TLS wraps it
		TLSClientConfig:   base.TLSClientConfig,
		ForceAttemptHTTP2: false,
	}
	cl, err := azsecrets.NewClient(srv.URL, fuzzAzureCred{}, &azsecrets.ClientOptions{
		DisableChallengeResourceVerification: true,
		ClientOptions: azcore.ClientOptions{
			Transport: &http.Client{Transport: tr, CheckRedirect: refuseRedirect},
			Retry:     retry,
		},
	})
	if err != nil {
		t.Fatalf("azsecrets.NewClient: %v", err)
	}
	return cl
}

// FuzzResguardAzureConnectorResponse is RSG2 Pilot #2's fuzz target. It runs with
// the CORRECT retry config (RetryDelay 1 ms, MaxRetryDelay 1 ms) and asserts that
// no fuzzed (status, body) can drive the metered backoff above a calibrated,
// input-size-INDEPENDENT ceiling (sleep_ns in ModeAbsolute), nor leak goroutines/
// fds, nor dial a non-loopback host. The SDK-bug demonstration (RetryDelay -1 ->
// 60 s intended backoff) is the separate TestResguardAzureSleepRedGreen.
func FuzzResguardAzureConnectorResponse(f *testing.F) {
	f.Add(200, []byte(`{"value":"s3cr3t","id":"https://v.vault.azure.net/secrets/db/abc123"}`))
	f.Add(500, []byte(``))          // retriable -> exercises the metered backoff
	f.Add(503, []byte(`slow down`)) // retriable
	f.Add(404, []byte(`{"error":{"code":"SecretNotFound"}}`))
	f.Add(200, []byte(`{"value":null}`))
	f.Add(200, []byte(`not json`))
	f.Add(429, []byte(``)) // retriable

	installAzureRetryDelayListener()
	nm := resguard.NewNetMeter() // air-gap: non-loopback dials fail
	probe := resguard.New(f, resguard.Options{SampleEvery: 32, Net: nm, Clock: azureSleepClock})

	budget, err := resguard.LoadBudget(azurePilotBudgetPath)
	if err != nil {
		f.Fatalf("no usable committed budget at %s (regenerate with TestResguardAzureCalibrate and RESGUARD_CALIBRATE=1): %v", azurePilotBudgetPath, err)
	}

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := clampHTTPStatus(status)
		var hits, challengeHits int32
		srv := azureFakeKV(code, body, &hits, &challengeHits)
		defer srv.Close()

		cl := azureMeteredClient(t, srv, nm, policy.RetryOptions{
			MaxRetries: 2, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond,
		})
		c := NewAzureKeyVaultConnector("fuzz", srv.URL, nil)
		c.newClient = func(_ context.Context) (azSecretGetter, error) { return cl, nil }

		var val string
		var gerr error
		cost := probe.Measure(len(body), func() {
			fuzzutil.Guard(t.Fatalf, "AzureKeyVaultConnector.GetSecret", func() {
				val, gerr = c.GetSecret(context.Background(), "fuzz-secret")
			})
		})
		resguard.FeedCoverage(cost)

		// Fail-closed (oracle b): non-200 must error; a 200 with no usable value must error.
		if code != http.StatusOK && gerr == nil {
			t.Fatalf("BYPASS: non-200 status %d treated as success, value %q", code, val)
		}
		var ref azureSecretValueRef
		hasValue := json.Unmarshal(body, &ref) == nil && ref.Value != nil && *ref.Value != ""
		if code == http.StatusOK && !hasValue && gerr == nil {
			t.Fatalf("BYPASS: 200 with no non-null,non-empty value returned success %q", val)
		}
		// Credential never echoed (oracle d).
		if gerr != nil && strings.Contains(gerr.Error(), azureFuzzBearerToken) {
			t.Fatalf("LEAK: bearer token appeared in error: %v", gerr)
		}
		// Bounded retries (oracle a).
		if h := atomic.LoadInt32(&hits); h > connectRetryCeiling {
			t.Fatalf("RETRY STORM: authenticated path hit %d times", h)
		}

		// Air-gap: the connector must never dial a non-loopback host.
		if cost.NonLoopbackDials > 0 {
			t.Fatalf("AIR-GAP: connector made %d non-loopback dial(s)", cost.NonLoopbackDials)
		}
		// Virtual-sleep budget: the metered intended backoff must stay bounded.
		budget.Check(t.Fatalf, cost)
		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines", n)
		}
		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d descriptors", fd)
		}
	})
}

const azurePilotBudgetPath = "testdata/resguard-azure-connector.json"
