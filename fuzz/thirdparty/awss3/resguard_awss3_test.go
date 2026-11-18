package awss3hostile

// resguard_awss3_test.go — PK1 port of FuzzS3PutObjectResponse onto the shared
// resguard resource layer. This is a cloudfuzz-family connector (signature
// (status, body) + RunGuarded + an existing redirect/retry-storm/leak oracle set).
// PK1 ADDS memory/CPU metering (alloc_bytes/mallocs + cpu_ns advisory) around the
// guarded PutObject call; every existing oracle is kept verbatim.
//
// Network is NOT wired through a NetMeter here: the harness already runs a
// dedicated cross-host "attacker" httptest server and FAILS the input if the SDK
// follows a redirect to it (the REDIRECT FOLLOWED oracle) — that is the air-gap
// equivalent for this family, and both endpoints are loopback httptest so a
// NetMeter air-gap could not distinguish them anyway. Stated, not silently dropped.
//
// Budget model: per-byte slope on alloc_bytes/mallocs (XML error-body parser).
// live_heap dropped (whole-process). What it does NOT verify: correctness; alloc
// sampled; CPU advisory/process-wide; alloc not separable between server, SDK and
// XML decoder.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const s3BudgetPath = "testdata/resguard-awss3-putobject.json"

var cloudfuzzMemMeters = []string{"alloc_bytes", "mallocs", "cpu_ns"}

func s3ResguardProbe(f *testing.F) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(s3BudgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", s3BudgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

// s3DriveBenign measures one benign PutObject against a single loopback server
// returning (code, body). Used by calibration/red-green only.
func s3DriveBenign(t *testing.T, probe *resguard.Probe, code int, body []byte) resguard.Cost {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = r.Body.Read(make([]byte, 0))
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	cl := s3.New(s3.Options{
		Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(s3FuzzAccessKeyID, s3FuzzSecretKey, ""),
		BaseEndpoint: aws.String(srv.URL), UsePathStyle: true,
		Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = 3
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		}),
	})
	return probe.Measure(len(body), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = cl.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("evidence-bucket"), Key: aws.String("packs/x.json"),
			Body: bytes.NewReader([]byte(`{"evidence":"pack"}`)), ContentType: aws.String("application/json"),
		})
	})
}

func s3BenignSeeds() []struct {
	code int
	body []byte
} {
	return []struct {
		code int
		body []byte
	}{
		{200, []byte(``)},
		{403, []byte(`<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>no</Message></Error>`)},
		{404, []byte(`<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>`)},
		{500, []byte(`<?xml version="1.0"?><Error><Code>InternalError</Code></Error>`)},
	}
}

func calibrateS3(t testing.TB) resguard.Budget {
	t.Helper()
	tt := t.(*testing.T)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	var costs []resguard.Cost
	for range 3 {
		for _, s := range s3BenignSeeds() {
			costs = append(costs, s3DriveBenign(tt, probe, s.code, s.body))
		}
	}
	b := resguard.Calibrate("awss3_putobject", costs, resguard.DefaultFactor)
	b.KeepOnly(cloudfuzzMemMeters...)
	return b
}

func TestResguardS3Calibrate(t *testing.T) {
	b := calibrateS3(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no meter calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(s3BudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", s3BudgetPath, b.Summary())
	}
}

// TestResguardS3RedGreen is the committed red/green for the cloudfuzz-family memory
// oracle (awss3 as representative; awskms/azurekeys share the identical wrap).
func TestResguardS3RedGreen(t *testing.T) {
	b := calibrateS3(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := s3DriveBenign(t, probe, 403, s3BenignSeeds()[1].body)
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign PutObject (alloc=%d) must pass", green.AllocBytes)
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
	t.Logf("GREEN alloc=%d passes; RED alloc=%d fires: %s", green.AllocBytes, red.AllocBytes, msg)
}
