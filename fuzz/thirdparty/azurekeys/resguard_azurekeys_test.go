package azurekeyshostile

// resguard_azurekeys_test.go — PK1 port of FuzzAzureKeysResponse onto the shared
// resguard resource layer (cloudfuzz family, same shape as awss3/awskms).
// Memory/CPU metered around the two guarded azkeys ops; every existing oracle
// (BYPASS, retry storm, canary leak, no-leak) is kept. Budget: per-byte slope on
// alloc_bytes/mallocs. Red/green is the family proof in awss3
// (TestResguardS3RedGreen); this package carries calibration + the live wrap.
//
// What it does NOT verify: correctness; alloc sampled; CPU advisory/process-wide;
// alloc spans both ops per input (inputLen is len(body)).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const azkeysBudgetPath = "testdata/resguard-azurekeys-response.json"

func azkeysResguardProbe(f *testing.F) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(azkeysBudgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", azkeysBudgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

func azkeysDriveBenign(t *testing.T, probe *resguard.Probe, code int, body []byte) resguard.Cost {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	cl, err := azkeys.NewClient(srv.URL, fakeCred{}, &azkeys.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: srv.Client(),
			Retry:     policy.RetryOptions{MaxRetries: 2, RetryDelay: time.Millisecond, TryTimeout: 2 * time.Second, MaxRetryDelay: 5 * time.Millisecond},
		},
	})
	if err != nil {
		t.Fatalf("harness bug: azkeys.NewClient: %v", err)
	}
	params := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("kek-material-32-bytes-padding-xxx"),
	}
	return probe.Measure(len(body), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = cl.WrapKey(ctx, "fuzzkey", "", params, nil)
		_, _ = cl.UnwrapKey(ctx, "fuzzkey", "", params, nil)
	})
}

func azkeysBenignSeeds() []struct {
	code int
	body []byte
} {
	return []struct {
		code int
		body []byte
	}{
		{200, []byte(`{"kid":"https://v.vault.azure.net/keys/k/abc","value":"d3JhcHBlZA"}`)},
		{200, []byte(`{"value":"dW53cmFwcGVk"}`)},
		{400, []byte(`{"error":{"code":"BadParameter","message":"x"}}`)},
		{500, []byte(``)},
	}
}

func calibrateAzkeys(t testing.TB) resguard.Budget {
	t.Helper()
	tt := t.(*testing.T)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	var costs []resguard.Cost
	for range 3 {
		for _, s := range azkeysBenignSeeds() {
			costs = append(costs, azkeysDriveBenign(tt, probe, s.code, s.body))
		}
	}
	b := resguard.Calibrate("azurekeys_response", costs, resguard.DefaultFactor)
	b.KeepOnly("alloc_bytes", "mallocs", "cpu_ns")
	return b
}

func TestResguardAzkeysCalibrate(t *testing.T) {
	b := calibrateAzkeys(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no meter calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(azkeysBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", azkeysBudgetPath, b.Summary())
	}
}
