package azurefuzz

// Fuzz target driving the real Azure azsecrets Key Vault client (over azcore's
// HTTP pipeline: retry policy + bearer-token challenge-authentication policy)
// against the hostile loopback server in fakeserver.go. Only the public client
// API is used; no Keyorix code is in the loop.
//
//   FuzzAzureGetSecret  azsecrets.Client.GetSecret
//
// The bearer token handed to the client is a high-entropy canary; the fuzzer
// controls the WWW-Authenticate challenge header (paired with a 401 it drives
// azcore's keyvault challenge parser), the status, headers, body and framing.
//
// ORACLES (and what each does NOT verify) — same four classes as the AWS harness:
//
//  (a) no-panic / no-hang: op under a 6s ctx + bounded azcore retry (2 retries,
//      3s TryTimeout) + 4s HTTP timeout, watched by a 20s watchdog. A panic in
//      the SDK fails the test; watchdog overrun = HANG. Does NOT measure RSS
//      precisely (attacker bytes capped at 64KB/response by the decoder; the
//      WWW-Authenticate value is capped at 256 bytes).
//
//  (b) canary: asserts the bearer-token canary (and a secondary credential
//      canary) never appears in a returned error string or fmt %+v of the
//      returned response. Does NOT inspect the Authorization header the client
//      legitimately sends, goroutine stacks, or process memory.
//
//  (c) echo class: server body text copied into a *azcore.ResponseError is
//      EXPECTED and logged under "echo:", never a finding.
//
//  (d) ignored-read-error: when the final response the client received declared
//      more body than it delivered (keyed on fakeServer.lastResponseTruncated,
//      which mirrors writeResponse incl. net/http's no-body-status rule), the
//      client MUST error rather than return a truncated-but-successful secret.
//      Does NOT assert the error's type/text; excludes raw-framing mode.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// errKnownChallengePanic is returned in place of the already-documented library
// panic in keyvault/internal challenge_policy.go parseTenant (see
// repro_panic_test.go and the h3 report, finding AZURE-1). Recovering ONLY this
// specific, stack-verified panic lets the fuzzer keep hunting for other classes
// of defect instead of halting on the same known one every run. Any other panic
// is re-raised so the oracle still catches novel crashes.
var errKnownChallengePanic = errors.New("known library panic: keyvault challenge_policy parseTenant index-out-of-range")

// callGetSecret runs the op, converting the known parseTenant panic into
// errKnownChallengePanic and re-panicking on anything else.
func callGetSecret(cl *azsecrets.Client, ctx context.Context) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			msg := fmt.Sprint(r)
			if strings.Contains(stack, "challenge_policy.go") && strings.Contains(msg, "index out of range") {
				err = errKnownChallengePanic
				return
			}
			panic(r) // novel panic -> let the watchdog/oracle fail the test
		}
	}()
	return cl.GetSecret(ctx, canaryName, "", nil)
}

const (
	canaryToken     = "CANARY-azure-bearer-token-do-not-leak-4b7a2c9e1f"
	canaryCredExtra = "CANARY-azure-cred-material-do-not-leak-8d3f6a0b5c"
	canaryName      = "fuzz-secret-name"
)

var canaries = []string{canaryToken, canaryCredExtra}

// fakeCred is a non-network azcore.TokenCredential that always returns the
// canary bearer token, so the fuzzer attacks azcore/azsecrets response + auth-
// challenge parsing without any real identity provider in the loop.
type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// Fixed far-future expiry (no Date.now in fuzz scripts, but tests may use a
	// literal date); keeps the token from being treated as expired.
	return azcore.AccessToken{
		Token:     canaryToken,
		ExpiresOn: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func httpClient() *http.Client {
	// Trust the fake server's self-signed loopback cert. azcore requires TLS to
	// attach the bearer token (see fakeserver.go); InsecureSkipVerify keeps the
	// attack surface (response/challenge parsing) in scope without a real CA.
	return &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback fuzz fake
		},
	}
}

func newVaultClient(vaultURL string) (*azsecrets.Client, error) {
	return azsecrets.NewClient(vaultURL, fakeCred{}, &azsecrets.ClientOptions{
		// Disable challenge-resource-verification so the fuzzer's parsed
		// WWW-Authenticate drives the FULL auth path (token attached, retry
		// issued) against our loopback host, rather than being short-circuited
		// by the host-domain check — maximising reach into the challenge parser
		// and the authenticated-retry response handling. (The verification is a
		// correct defence in production; we switch it off here only to widen the
		// fuzzed surface.)
		DisableChallengeResourceVerification: true,
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient(),
			Retry: policy.RetryOptions{
				MaxRetries:    2,
				TryTimeout:    3 * time.Second,
				RetryDelay:    time.Millisecond,
				MaxRetryDelay: 2 * time.Millisecond,
			},
		},
	})
}

// newVerifyingVaultClient builds a client with the PRODUCTION-DEFAULT
// challenge-resource verification ENABLED (DisableChallengeResourceVerification
// unset = false), matching Keyorix's configuration. Used by the repro that
// demonstrates AZURE-1 is reachable even under verification.
func newVerifyingVaultClient(vaultURL string) (*azsecrets.Client, error) {
	return azsecrets.NewClient(vaultURL, fakeCred{}, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient(),
			Retry: policy.RetryOptions{
				MaxRetries:    2,
				TryTimeout:    3 * time.Second,
				RetryDelay:    time.Millisecond,
				MaxRetryDelay: 2 * time.Millisecond,
			},
		},
	})
}

// --- oracle machinery (mirrors the AWS harness) ---

type oracleResult struct {
	findings []string
	echoed   bool
}

func evalOracles(label string, specs []respSpec, out any, err error, lastTruncated bool) oracleResult {
	var res oracleResult
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
	if err != nil {
		for _, s := range specs {
			if len(s.body) >= 6 && !s.raw && strings.Contains(err.Error(), string(s.body)) {
				res.echoed = true
				break
			}
		}
	}
	if lastTruncated && err == nil {
		res.findings = append(res.findings,
			fmt.Sprintf("IGNORED READ ERROR in %s: server truncated the final response body but client reported success (out=%+v)", label, out))
	}
	return res
}

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
	select {
	case <-done:
		if err != nil && strings.HasPrefix(err.Error(), "PANIC") {
			t.Fatalf("%v", err)
		}
		return out, err, false
	case <-time.After(20 * time.Second):
		return nil, nil, true
	}
}

func FuzzAzureGetSecret(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		specs := decodeSpecs(data)
		fs, err := newFakeServer(specs)
		if err != nil {
			t.Skip()
		}
		defer fs.Close()
		cl, err := newVaultClient(fs.url())
		if err != nil {
			// A client-construction error (e.g. URL rejected) is not a server-
			// driven fuzz finding; skip. The canary cannot have leaked here.
			t.Skip()
		}
		out, oerr, timedOut := runWithWatchdog(t, "GetSecret", func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			return callGetSecret(cl, ctx)
		})
		checkOracles(t, "GetSecret", specs, out, oerr, timedOut, fs.lastResponseTruncated())
	})
}
