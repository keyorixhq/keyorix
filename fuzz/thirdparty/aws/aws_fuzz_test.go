package awsfuzz

// Fuzz targets that drive the real AWS SDK for Go v2 service clients against the
// hostile loopback server in fakeserver.go. Each target speaks one SDK
// protocol shape:
//
//   FuzzSecretsManager  secretsmanager.GetSecretValue  (AWS JSON 1.1)
//   FuzzSTS             sts.AssumeRole                 (AWS Query / XML)
//   FuzzKMS             kms.Decrypt                    (AWS JSON 1.1, blob I/O)
//
// Only the public client API is used; no Keyorix code is in the loop.
//
// ORACLES (and what each does NOT verify):
//
//  (a) no-panic / no-hang: the whole operation is run under a 4s client
//      timeout and watched by a 20s watchdog. A panic from inside the SDK
//      fails the test; exceeding the watchdog is reported as a hang. This does
//      NOT verify tight latency, and it does NOT measure memory precisely —
//      attacker bytes are capped at 64KB per response by the decoder, so
//      "unbounded allocation from a length field" is probed via the
//      lying-Content-Length / truncated-chunk paths (the client must return an
//      error, not a body) rather than by measuring RSS.
//
//  (b) canary: the client is built with static credentials whose secret key and
//      session token are high-entropy canaries. The oracle asserts neither
//      canary ever appears in a returned error string or in fmt %+v of a
//      returned output struct. It does NOT inspect the raw request the SDK put
//      on the wire (SigV4 signing legitimately derives an HMAC from the key),
//      and it does NOT check process memory or goroutine stacks.
//
//  (c) echo class: server-controlled body text that the SDK copies into an
//      error message is EXPECTED (AWS error shapes echo a server "message").
//      It is recorded via t.Log under an "echo:" tag and never fails the test —
//      only a leak of the client-side canary (b) is a finding.
//
//  (d) ignored-read-error: when the LAST response the client received declared
//      more body than it delivered (lying Content-Length, or a chunked body
//      whose announced chunk exceeds the bytes sent before the connection
//      closes), the client MUST surface an error rather than a
//      truncated-but-successful result. Keyed on the server's record of the
//      final response actually served (fakeServer.lastResponseTruncated), not on
//      "some truncating spec exists", so a round-robin retry that ends on a
//      clean response cannot false-positive. closeAfterBody with an accurate
//      Content-Length is a COMPLETE response (HTTP/1.0-style close) and is NOT
//      treated as truncation. It does NOT assert anything about the error's
//      type or text, and excludes raw-framing mode.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// Canaries: client-side secrets that must never surface in errors or output.
const (
	canaryAccessKey = "AKIA_CANARY_ACCESS_KEY_ID_000000"
	canarySecretKey = "CANARY-sEcReT-kEy-aws-do-not-leak-9f3a1b2c4d"
	canaryToken     = "CANARY-session-token-aws-do-not-leak-7e6d5c4b3a"
	// canaryRef is attacker-visible (it goes on the wire as SecretId) — it is
	// NOT a secret, so it is excluded from the leak oracle; included only so a
	// grep of errors shows which call produced them.
	canaryRef = "fuzz-ref"
)

var canaries = []string{canarySecretKey, canaryToken}

func staticCreds() aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(canaryAccessKey, canarySecretKey, canaryToken)
}

// zeroBackoff keeps retries fast so a retried response sequence cannot stall the
// fuzzer; we still exercise the retry path (up to 3 attempts).
type zeroBackoff struct{}

func (zeroBackoff) BackoffDelay(int, error) (time.Duration, error) { return 0, nil }

func boundedRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 3
		o.Backoff = zeroBackoff{}
	})
}

func httpClient() *http.Client {
	// PK1: route the dial through the package-global air-gapped NetMeter (awsNet)
	// so a non-loopback dial fails the air-gap oracle and request/response byte
	// volume is metered per input. The fake server is loopback HTTP, so the dial
	// passes the air-gap unchanged.
	return &http.Client{
		Timeout:   4 * time.Second,
		Transport: &http.Transport{DialContext: awsNet.DialContext},
	}
}

// runWithWatchdog runs fn and fails on panic or on exceeding the hang bound.
func runWithWatchdog(t *testing.T, label string, fn func() (any, error)) (out any, err error, timedOut bool) {
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("PANIC in %s: %v", label, r)
			}
			close(done)
		}()
		out, err = fn()
	}()
	if _, ok, _ := fuzzutil.Wait(done, 20*time.Second); !ok {
		return nil, nil, true
	}
	if err != nil && strings.HasPrefix(err.Error(), "PANIC") {
		t.Fatalf("%v", err)
	}
	return out, err, false
}

// oracleResult is the pure (t-free) verdict of the oracles, so the oracle logic
// itself can be unit-tested red/green without a live SDK call.
type oracleResult struct {
	findings []string // fatal: canary leak (b) or ignored-read-error (d)
	echoed   bool     // informational: server body copied into error (c)
}

func evalOracles(label string, specs []respSpec, out any, err error, lastTruncated bool) oracleResult {
	var res oracleResult
	// (b) canary leak
	hay := ""
	if err != nil {
		hay += err.Error()
	}
	if out != nil {
		hay += fmt.Sprintf("%+v", out)
	}
	for _, c := range canaries {
		if strings.Contains(hay, c) {
			res.findings = append(res.findings,
				fmt.Sprintf("CANARY LEAK in %s: secret %q appeared in error/output: %q", label, c, hay))
		}
	}
	// (c) echo class — informational only
	if err != nil {
		for _, s := range specs {
			if len(s.body) >= 6 && !s.raw && strings.Contains(err.Error(), string(s.body)) {
				res.echoed = true
				break
			}
		}
	}
	// (d) ignored-read-error — keyed on the LAST response the client received
	// (not "any truncating spec exists"), so round-robin + retry can't false-
	// positive when a later clean response is what the client acted on.
	if lastTruncated && err == nil {
		res.findings = append(res.findings,
			fmt.Sprintf("IGNORED READ ERROR in %s: server truncated the final response body but client reported success (out=%+v)", label, out))
	}
	return res
}

// checkOracles runs the leak (b), echo (c) and ignored-read-error (d) oracles.
func checkOracles(t *testing.T, label string, specs []respSpec, out any, err error, timedOut bool, lastTruncated bool) {
	if timedOut {
		t.Fatalf("HANG: %s did not return within watchdog bound", label)
	}
	res := evalOracles(label, specs, out, err, lastTruncated)
	if res.echoed {
		t.Logf("echo: %s copied server body into error (expected, not a bug)", label)
	}
	if len(res.findings) > 0 {
		t.Fatalf("%s", strings.Join(res.findings, "\n"))
	}
}

func FuzzSecretsManager(f *testing.F) {
	seedCorpus(f)
	probe, budget, haveBudget := awsResguardProbe(f, awsBudgetSecretsManager)
	f.Fuzz(func(t *testing.T, data []byte) {
		specs := decodeSpecs(data)
		fs, err := newFakeServer(specs)
		if err != nil {
			t.Skip()
		}
		defer fs.Close()
		cl := secretsmanager.New(secretsmanager.Options{
			Region:       "us-east-1",
			Credentials:  staticCreds(),
			BaseEndpoint: aws.String(fs.url()),
			HTTPClient:   httpClient(),
			Retryer:      boundedRetryer(),
		})
		var out any
		var oerr error
		var timedOut bool
		cost := probe.Measure(len(data), func() {
			out, oerr, timedOut = runWithWatchdog(t, "GetSecretValue", func() (any, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				return cl.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(canaryRef)})
			})
		})
		resguard.FeedCoverage(cost)
		checkOracles(t, "GetSecretValue", specs, nilIfErr(out), oerr, timedOut, fs.lastResponseTruncated())
		awsResguardCheck(t, budget, haveBudget, cost, "SecretsManager")
	})
}

func FuzzSTS(f *testing.F) {
	seedCorpus(f)
	probe, budget, haveBudget := awsResguardProbe(f, awsBudgetSTS)
	f.Fuzz(func(t *testing.T, data []byte) {
		specs := decodeSpecs(data)
		fs, err := newFakeServer(specs)
		if err != nil {
			t.Skip()
		}
		defer fs.Close()
		cl := sts.New(sts.Options{
			Region:       "us-east-1",
			Credentials:  staticCreds(),
			BaseEndpoint: aws.String(fs.url()),
			HTTPClient:   httpClient(),
			Retryer:      boundedRetryer(),
		})
		var out any
		var oerr error
		var timedOut bool
		cost := probe.Measure(len(data), func() {
			out, oerr, timedOut = runWithWatchdog(t, "AssumeRole", func() (any, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				return cl.AssumeRole(ctx, &sts.AssumeRoleInput{
					RoleArn:         aws.String("arn:aws:iam::123456789012:role/" + canaryRef),
					RoleSessionName: aws.String("fuzz"),
				})
			})
		})
		resguard.FeedCoverage(cost)
		checkOracles(t, "AssumeRole", specs, nilIfErr(out), oerr, timedOut, fs.lastResponseTruncated())
		awsResguardCheck(t, budget, haveBudget, cost, "STS")
	})
}

func FuzzKMS(f *testing.F) {
	seedCorpus(f)
	probe, budget, haveBudget := awsResguardProbe(f, awsBudgetKMS)
	f.Fuzz(func(t *testing.T, data []byte) {
		specs := decodeSpecs(data)
		fs, err := newFakeServer(specs)
		if err != nil {
			t.Skip()
		}
		defer fs.Close()
		cl := kms.New(kms.Options{
			Region:       "us-east-1",
			Credentials:  staticCreds(),
			BaseEndpoint: aws.String(fs.url()),
			HTTPClient:   httpClient(),
			Retryer:      boundedRetryer(),
		})
		var out any
		var oerr error
		var timedOut bool
		cost := probe.Measure(len(data), func() {
			out, oerr, timedOut = runWithWatchdog(t, "Decrypt", func() (any, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				return cl.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: []byte("fuzz-ciphertext-blob")})
			})
		})
		resguard.FeedCoverage(cost)
		checkOracles(t, "Decrypt", specs, nilIfErr(out), oerr, timedOut, fs.lastResponseTruncated())
		awsResguardCheck(t, budget, haveBudget, cost, "KMS")
	})
}

// nilIfErr returns out as-is; it exists only to document that a typed-nil
// pointer output is harmless for fmt (%+v on a nil pointer prints "<nil>").
func nilIfErr(out any) any { return out }

// sanity compile-time use of errors to keep import if unused in some builds.
var _ = errors.Is
