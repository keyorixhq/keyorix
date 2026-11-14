// Hostile-SERVER fuzz harness for github.com/aws/aws-sdk-go-v2/service/s3, the
// SDK Keyorix uses to forward signed evidence packs to an OPERATOR-CONFIGURED
// object store (internal/evidencesink/objectstore.go: ForwardEvidence →
// s3.PutObject). The endpoint is the single most operator-/attacker-influenceable
// AWS surface in the codebase: evidencesink.Config.Endpoint is a free-form URL
// (S3-compatible: MinIO, R2, B2, GCS interop), set straight into s3.Options
// BaseEndpoint.
//
// Threat model: that object-store endpoint is attacker-controlled and replies
// with hostile REST-XML bodies — a mutated/garbage/truncated XML error document,
// wrong content-type, a deeply nested XML tree, a 3xx redirect to an attacker
// host. This harness drives a REAL s3.Client (constructed as evidencesink does —
// BaseEndpoint + UsePathStyle, here with static canary credentials and a bounded
// retryer) against an httptest.Server whose status and body are fuzzer-controlled,
// and calls PutObject exactly as ForwardEvidence does. This exercises the smithy-go
// REST-XML error deserializer — a DIFFERENT protocol from the awsJson1_1 path the
// KMS/Secrets-Manager targets cover.
//
// Oracles (sound only):
//   - Panic: no panic escapes the SDK's documented error return (RunGuarded).
//   - Bounded time: PutObject returns within the guard deadline even against a
//     huge/deeply-nested XML body (retries bounded; zero-delay backoff).
//   - No goroutine / fd leak after the call returns (CheckNoLeak).
//   - Fail-closed on non-2xx: the REST-XML deserializer routes any status outside
//     [200,300) to the error path, so PutObject MUST return an error on such a
//     status (ForwardEvidence propagates it — a failed upload must never look like
//     a successful WORM write).
//   - No retry storm: the fake endpoint is hit at most s3RetryCeiling times.
//   - Credential confidentiality: the static AWS access-key id must never appear
//     in a returned error, and a 3xx redirect to a cross-host attacker target must
//     never be followed.
//
// What these oracles do NOT verify (stated, per the method):
//   - NOT REST-XML SUCCESS-body decode (GetObject/ListObjects/GetBucketLocation):
//     Keyorix only ever calls PutObject on this endpoint, whose success response
//     carries metadata in HEADERS, not an XML body — so the XML *element* decoder
//     is only reachable via the error path, which is what is fuzzed. Success-body
//     XML decode has no live Keyorix caller and is out of scope.
//   - NOT the pinned-dial DNS-rebinding protection (pinnedDialContext): that is an
//     evidencesink transport property, asserted in evidencesink's own tests, not a
//     response-decode property.
//   - NOT Object-Lock / retention semantics of the written object.
//   - NOT credentials from the real AWS chain (static credentials injected).
package awss3hostile

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/cloudfuzz"
)

const (
	s3FuzzAccessKeyID = "AKIAS3FUZZCANARY42Z"
	s3FuzzSecretKey   = "fuzzS3SecretAccessKeyCanary7e91xyfuzzS3Secretxx"
	s3RetryCeiling    = 10
)

func FuzzS3PutObjectResponse(f *testing.F) {
	f.Add(200, []byte(``))                                                          // typical PutObject success (metadata in headers)
	f.Add(403, []byte(`<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>no</Message></Error>`))
	f.Add(404, []byte(`<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>`))
	f.Add(500, []byte(`<?xml version="1.0"?><Error><Code>InternalError</Code></Error>`))
	f.Add(400, []byte(`not xml at all`))
	f.Add(400, []byte(`<Error><Code>Trunc`))                                        // truncated XML
	f.Add(400, []byte(`<?xml version="1.0"?><Error><Code>X</Code><Message>&lt;nested&gt;</Message></Error>`))
	f.Add(503, []byte(`<?xml version="1.0"?><Error><Code>SlowDown</Code></Error>`)) // retryable
	f.Add(307, []byte(``))
	f.Add(308, []byte(``))
	f.Add(200, []byte(`<?xml version="1.0"?><CompleteMultipartUploadResult><ETag>"x"</ETag></CompleteMultipartUploadResult>`))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := cloudfuzz.ClampHTTPStatus(status)

		var attackerHits atomic.Int32
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attackerHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer attacker.Close()

		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_, _ = r.Body.Read(make([]byte, 0)) // touch body; discarded on close
			if code == http.StatusTemporaryRedirect || code == http.StatusPermanentRedirect {
				w.Header().Set("Location", attacker.URL)
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cl := s3.New(s3.Options{
			Region:       "us-east-1",
			Credentials:  credentials.NewStaticCredentialsProvider(s3FuzzAccessKeyID, s3FuzzSecretKey, ""),
			BaseEndpoint: aws.String(srv.URL),
			UsePathStyle: true,
			Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			}),
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var err error
		cloudfuzz.RunGuarded(t, "s3.PutObject", func() {
			_, err = cl.PutObject(ctx, &s3.PutObjectInput{
				Bucket:      aws.String("evidence-bucket"),
				Key:         aws.String("packs/evidence-2026.json"),
				Body:        bytes.NewReader([]byte(`{"evidence":"pack"}`)),
				ContentType: aws.String("application/json"),
			})
		})

		if (code < 200 || code >= 300) && err == nil {
			t.Fatalf("BYPASS: s3.PutObject treated non-2xx status %d as a successful upload", code)
		}
		cloudfuzz.AssertNoSecretInError(t, "s3.PutObject", err, s3FuzzAccessKeyID, s3FuzzSecretKey)
		if h := hits.Load(); h > s3RetryCeiling {
			t.Fatalf("RETRY STORM: s3.PutObject hit the fake endpoint %d times (MaxAttempts=3)", h)
		}
		if h := attackerHits.Load(); h > 0 {
			t.Fatalf("REDIRECT FOLLOWED: s3.PutObject reached the cross-host attacker target (hits=%d)", h)
		}
		cloudfuzz.CheckNoLeak(t, "s3.PutObject")
	})
}
