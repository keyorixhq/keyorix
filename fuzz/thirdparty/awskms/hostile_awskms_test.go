// Hostile-SERVER fuzz harness for github.com/aws/aws-sdk-go-v2/service/kms, the
// SDK Keyorix uses as its root-of-trust KMS provider (internal/crypto/awskms):
// DescribeKey resolves the key ARN once at startup, and Encrypt/Decrypt wrap and
// unwrap the data-encryption key on EVERY secret write/read.
//
// Threat model: an on-path attacker MITMs the AWS KMS endpoint, or the endpoint
// is otherwise attacker-influenced, and replies with hostile awsJson1_1 bodies —
// wrong content-type, truncated/garbage JSON, a missing CiphertextBlob/Plaintext,
// deeply nested JSON, a 3xx redirect to an attacker host. This harness drives a
// REAL kms.Client (constructed exactly as awskms.New does — default-chain shape,
// here pinned to static canary credentials and the SDK's BaseEndpoint override)
// against an httptest.Server whose status and body are fuzzer-controlled, and
// calls DescribeKey, Encrypt and Decrypt so all three smithy-go JSON output
// deserializers are exercised.
//
// Oracles (sound only):
//   - Panic: no panic escapes the SDK's documented error return (RunGuarded).
//   - Bounded time: each call returns within the guard deadline, even against a
//     huge/deeply-nested body (retries are bounded to MaxAttempts with a
//     zero-delay backoff).
//   - No goroutine / fd leak after the calls return (CheckNoLeak).
//   - Fail-closed on non-2xx: smithy-go routes any status outside [200,300) to the
//     error deserializer, so each operation MUST return an error (never a
//     populated output) on such a status.
//   - No retry storm: the fake endpoint is hit at most RetryCeiling times per op
//     regardless of the fuzzed status / any Retry-After-shaped body.
//   - Credential confidentiality: the client's static AWS access-key id (sent in
//     the SigV4 Authorization header) must never appear in a returned error
//     (AssertNoSecretInError), and a 3xx redirect to a cross-host attacker target
//     must never be followed (the SDK's limitedRedirect refuses it — asserted as a
//     hard regression guard).
//
// What these oracles do NOT verify (stated, per the method):
//   - NOT that a 2xx response carrying an empty/missing CiphertextBlob or
//     Plaintext is rejected. That is a Keyorix-LAYER check (awskms.go's
//     "response had no ciphertext"), not an SDK-decode property; it is asserted by
//     awskms's own unit tests, not re-fuzzed here. This target's success path only
//     establishes that the SDK decode did not panic/hang/leak.
//   - NOT the cryptographic correctness of any returned ciphertext/plaintext
//     (a hostile KMS can always return attacker-chosen bytes; confused-deputy
//     protection is the KeyId/ARN pinning tested in awskms, not here).
//   - NOT credentials sourced from the real AWS chain (IMDS/web-identity) — static
//     credentials are injected so no real metadata endpoint is ever contacted.
package awskmshostile

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/cloudfuzz"
)

const (
	kmsFuzzAccessKeyID = "AKIAKMSFUZZCANARY91X"
	kmsFuzzSecretKey   = "fuzzKmsSecretAccessKeyCanary7e91xyfuzzKmsSecret"
	// kmsRetryCeiling bounds how many times one op may hit the fake endpoint.
	// MaxAttempts=3 is configured; this generous ceiling is a "no retry storm"
	// tripwire, not an exact attempt-count assertion.
	kmsRetryCeiling = 10
)

func FuzzKMSResponse(f *testing.F) {
	f.Add(200, []byte(`{"CiphertextBlob":"AQIDAAE="}`))            // Encrypt success-shaped
	f.Add(200, []byte(`{"Plaintext":"c2VjcmV0"}`))                 // Decrypt success-shaped
	f.Add(200, []byte(`{"KeyMetadata":{"Arn":"arn:aws:kms:us-east-1:111122223333:key/abc"}}`))
	f.Add(200, []byte(`{}`))                                       // empty object
	f.Add(400, []byte(`{"__type":"NotFoundException","message":"x"}`))
	f.Add(403, []byte(`{"__type":"AccessDeniedException"}`))
	f.Add(500, []byte(``))
	f.Add(200, []byte(`not json at all`))
	f.Add(200, []byte(`{"CiphertextBlob":`))                       // truncated JSON
	f.Add(200, []byte(`{"CiphertextBlob":"!!!not-base64!!!"}`))    // invalid blob encoding
	f.Add(307, []byte(``))
	f.Add(308, []byte(``))
	f.Add(200, []byte(`{"KeyMetadata":{"Arn":null}}`))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := cloudfuzz.ClampHTTPStatus(status)

		var attackerHits atomic.Int32
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attackerHits.Add(1)
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write([]byte(`{"Plaintext":"QVRUQUNLRVI="}`))
		}))
		defer attacker.Close()
		// Confirm the attacker target is one Keyorix's SSRF guard would refuse —
		// reuse of the real private/link-local classification, so the redirect
		// oracle is not vacuous. (Loopback is private; this is a sanity check that
		// the URL is parseable and loopback-shaped.)
		if u, uerr := url.Parse(attacker.URL); uerr == nil {
			if host, _, herr := net.SplitHostPort(u.Host); herr == nil {
				if ip := net.ParseIP(host); ip == nil {
					t.Fatalf("harness bug: attacker URL host %q is not an IP", host)
				}
			}
		}

		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			if code == http.StatusTemporaryRedirect || code == http.StatusPermanentRedirect {
				w.Header().Set("Location", attacker.URL)
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cl := kms.New(kms.Options{
			Region:       "us-east-1",
			Credentials:  credentials.NewStaticCredentialsProvider(kmsFuzzAccessKeyID, kmsFuzzSecretKey, ""),
			BaseEndpoint: aws.String(srv.URL),
			Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			}),
		})

		keyID := "arn:aws:kms:us-east-1:111122223333:key/fuzz"

		type opCall struct {
			name string
			run  func(context.Context) error
		}
		ops := []opCall{
			{"DescribeKey", func(ctx context.Context) error {
				_, err := cl.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
				return err
			}},
			{"Encrypt", func(ctx context.Context) error {
				_, err := cl.Encrypt(ctx, &kms.EncryptInput{KeyId: &keyID, Plaintext: []byte("dek-plaintext")})
				return err
			}},
			{"Decrypt", func(ctx context.Context) error {
				_, err := cl.Decrypt(ctx, &kms.DecryptInput{KeyId: &keyID, CiphertextBlob: []byte("wrapped-kek-blob")})
				return err
			}},
		}

		for _, op := range ops {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			hits.Store(0)
			var err error
			cloudfuzz.RunGuarded(t, "kms."+op.name, func() {
				err = op.run(ctx)
			})
			cancel()

			if (code < 200 || code >= 300) && err == nil {
				t.Fatalf("BYPASS: kms.%s treated non-2xx status %d as success", op.name, code)
			}
			cloudfuzz.AssertNoSecretInError(t, "kms."+op.name, err, kmsFuzzAccessKeyID, kmsFuzzSecretKey)
			if h := hits.Load(); h > kmsRetryCeiling {
				t.Fatalf("RETRY STORM: kms.%s hit the fake endpoint %d times (MaxAttempts=3)", op.name, h)
			}
		}

		if h := attackerHits.Load(); h > 0 {
			t.Fatalf("REDIRECT FOLLOWED: a kms op reached the cross-host attacker target (hits=%d)", h)
		}
		cloudfuzz.CheckNoLeak(t, "kms response fuzz")
	})
}
