package awskmshostile

// resguard_awskms_test.go — PK1 port of FuzzKMSResponse onto the shared resguard
// resource layer (cloudfuzz family, same shape as awss3). Memory/CPU metered
// (alloc_bytes/mallocs + cpu_ns advisory) around the three guarded KMS ops; every
// existing oracle (BYPASS, retry storm, canary leak, REDIRECT FOLLOWED) is kept.
// Network is covered by the existing cross-host redirect oracle (see the awss3
// resguard header for the family rationale). Budget: per-byte slope on
// alloc_bytes/mallocs. Red/green is the family proof in awss3
// (TestResguardS3RedGreen); this package carries calibration + the live wrap.
//
// What it does NOT verify: correctness; alloc sampled; CPU advisory/process-wide;
// alloc spans all three ops per input (inputLen is len(body), the shared response).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const kmsBudgetPath = "testdata/resguard-awskms-response.json"

func kmsResguardProbe(f *testing.F) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(kmsBudgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", kmsBudgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

func kmsDriveBenign(t *testing.T, probe *resguard.Probe, code int, body []byte) resguard.Cost {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	cl := kms.New(kms.Options{
		Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(kmsFuzzAccessKeyID, kmsFuzzSecretKey, ""),
		BaseEndpoint: aws.String(srv.URL),
		Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = 3
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		}),
	})
	keyID := "arn:aws:kms:us-east-1:111122223333:key/fuzz"
	return probe.Measure(len(body), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = cl.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
		_, _ = cl.Encrypt(ctx, &kms.EncryptInput{KeyId: &keyID, Plaintext: []byte("dek-plaintext")})
		_, _ = cl.Decrypt(ctx, &kms.DecryptInput{KeyId: &keyID, CiphertextBlob: []byte("wrapped-kek-blob")})
	})
}

func kmsBenignSeeds() []struct {
	code int
	body []byte
} {
	return []struct {
		code int
		body []byte
	}{
		{200, []byte(`{"CiphertextBlob":"AQIDAAE="}`)},
		{200, []byte(`{"KeyMetadata":{"Arn":"arn:aws:kms:us-east-1:111122223333:key/abc"}}`)},
		{400, []byte(`{"__type":"NotFoundException","message":"x"}`)},
		{500, []byte(``)},
	}
}

func calibrateKMS(t testing.TB) resguard.Budget {
	t.Helper()
	tt := t.(*testing.T)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	var costs []resguard.Cost
	for range 3 {
		for _, s := range kmsBenignSeeds() {
			costs = append(costs, kmsDriveBenign(tt, probe, s.code, s.body))
		}
	}
	b := resguard.Calibrate("awskms_response", costs, resguard.DefaultFactor)
	b.KeepOnly("alloc_bytes", "mallocs", "cpu_ns")
	return b
}

func TestResguardKMSCalibrate(t *testing.T) {
	b := calibrateKMS(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no meter calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(kmsBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", kmsBudgetPath, b.Summary())
	}
}
