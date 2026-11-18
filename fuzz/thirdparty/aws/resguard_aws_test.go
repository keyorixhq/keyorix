package awsfuzz

// resguard_aws_test.go — PK1 port of the AWS SDK connector fuzz targets
// (FuzzSecretsManager, FuzzSTS, FuzzKMS) onto the shared resguard resource layer
// with the CONNECTOR treatment (memory/CPU + network). httpClient()'s dial is
// routed through the package-global air-gapped awsNet so a non-loopback dial fails
// the air-gap oracle and request/response byte volume is metered per input.
//
// Existing canary/echo/no-panic/no-hang/ignored-read oracles (checkOracles) are
// UNCHANGED. Sleep is not metered: the SDK retry is a bounded boundedRetryer() and
// the 6 s ctx + 20 s watchdog bound the real sleep (stated, not dropped).
//
// What it does NOT verify: correctness; alloc is sampled; CPU process-wide
// advisory; NetMeter sees only dials routed through httpClient() and counts raw
// HTTP bytes (plaintext here — loopback HTTP, no TLS); alloc is not separable
// between the fake server, the SDK client and the decoder.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

var awsNet = resguard.NewNetMeter()

const (
	awsBudgetSecretsManager = "testdata/resguard-aws-secretsmanager.json"
	awsBudgetSTS            = "testdata/resguard-aws-sts.json"
	awsBudgetKMS            = "testdata/resguard-aws-kms.json"
)

var awsConnMeters = []string{"alloc_bytes", "mallocs", "cpu_ns", "net_bytes_in", "net_bytes_out"}

func awsResguardProbe(f *testing.F, budgetPath string) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32, Net: awsNet})
	b, err := resguard.LoadBudget(budgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", budgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

// awsResguardCheck applies the air-gap oracle (always) and the calibrated budget.
func awsResguardCheck(t *testing.T, budget resguard.Budget, haveBudget bool, cost resguard.Cost, label string) {
	if cost.NonLoopbackDials > 0 {
		t.Fatalf("AIR-GAP: %s connector made %d non-loopback dial(s)", label, cost.NonLoopbackDials)
	}
	if haveBudget {
		budget.Check(t.Fatalf, cost)
	}
}

// awsOpBuilder builds the per-target SDK op closure bound to the fake server URL.
type awsOpBuilder func(url string) func(ctx context.Context) (any, error)

func awsSecretsManagerOp(url string) func(ctx context.Context) (any, error) {
	cl := secretsmanager.New(secretsmanager.Options{
		Region: "us-east-1", Credentials: staticCreds(), BaseEndpoint: aws.String(url),
		HTTPClient: httpClient(), Retryer: boundedRetryer(),
	})
	return func(ctx context.Context) (any, error) {
		return cl.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(canaryRef)})
	}
}

func awsSTSOp(url string) func(ctx context.Context) (any, error) {
	cl := sts.New(sts.Options{
		Region: "us-east-1", Credentials: staticCreds(), BaseEndpoint: aws.String(url),
		HTTPClient: httpClient(), Retryer: boundedRetryer(),
	})
	return func(ctx context.Context) (any, error) {
		return cl.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn: aws.String("arn:aws:iam::123456789012:role/" + canaryRef), RoleSessionName: aws.String("fuzz"),
		})
	}
}

func awsKMSOp(url string) func(ctx context.Context) (any, error) {
	cl := kms.New(kms.Options{
		Region: "us-east-1", Credentials: staticCreds(), BaseEndpoint: aws.String(url),
		HTTPClient: httpClient(), Retryer: boundedRetryer(),
	})
	return func(ctx context.Context) (any, error) {
		return cl.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: []byte("fuzz-ciphertext-blob")})
	}
}

// awsBenignInputs: a 200 with a plausible service body and a 404 — the normal
// success/not-found replies, enough to calibrate the decode-path alloc + net bytes.
func awsBenignInputs() [][]byte {
	return [][]byte{
		encodeSeeds([]seedSpec{{status: 200, body: []byte(`{"SecretString":"s3cr3t","ARN":"arn:aws:secretsmanager:us-east-1:1:secret:x"}`)}}),
		encodeSeeds([]seedSpec{{status: 404, body: []byte(`{"__type":"ResourceNotFoundException"}`)}}),
		encodeSeeds([]seedSpec{{status: 500, body: []byte(`{"__type":"InternalFailure"}`)}}),
	}
}

func awsDriveMeasured(t *testing.T, probe *resguard.Probe, build awsOpBuilder, data []byte) resguard.Cost {
	t.Helper()
	specs := decodeSpecs(data)
	fs, err := newFakeServer(specs)
	if err != nil {
		return resguard.Cost{}
	}
	defer fs.Close()
	op := build(fs.url())
	return probe.Measure(len(data), func() {
		_, _, _ = runWithWatchdog(t, "calibrate", func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			return op(ctx)
		})
	})
}

func calibrateAWS(t testing.TB, name string, build awsOpBuilder) resguard.Budget {
	t.Helper()
	tt := t.(*testing.T)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: awsNet})
	var costs []resguard.Cost
	for range 3 {
		for _, data := range awsBenignInputs() {
			costs = append(costs, awsDriveMeasured(tt, probe, build, data))
		}
	}
	b := resguard.Calibrate(name, costs, resguard.DefaultFactor)
	b.KeepOnly(awsConnMeters...)
	return b
}

type awsCalTarget struct {
	name, path string
	build      awsOpBuilder
}

func awsCalTargets() []awsCalTarget {
	return []awsCalTarget{
		{"aws_secretsmanager", awsBudgetSecretsManager, awsSecretsManagerOp},
		{"aws_sts", awsBudgetSTS, awsSTSOp},
		{"aws_kms", awsBudgetKMS, awsKMSOp},
	}
}

func TestResguardAWSCalibrate(t *testing.T) {
	for _, tgt := range awsCalTargets() {
		b := calibrateAWS(t, tgt.name, tgt.build)
		if len(b.Meters) == 0 {
			t.Fatalf("%s: no meter calibrated; %s", tgt.name, b.Summary())
		}
		if os.Getenv("RESGUARD_CALIBRATE") == "1" {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := b.WriteJSON(tgt.path); err != nil {
				t.Fatalf("%s: write budget: %v", tgt.name, err)
			}
			t.Logf("wrote %s: %s", tgt.path, b.Summary())
		}
	}
}

func TestResguardAWSRedGreen(t *testing.T) {
	b := calibrateAWS(t, "aws_secretsmanager", awsSecretsManagerOp)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: awsNet})
	green := awsDriveMeasured(t, probe, awsSecretsManagerOp, awsBenignInputs()[0])
	if green.NonLoopbackDials != 0 {
		t.Fatalf("benign GetSecretValue must make no non-loopback dial, got %d", green.NonLoopbackDials)
	}
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign GetSecretValue (alloc=%d net_in=%d) must pass", green.AllocBytes, green.NetBytesIn)
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
