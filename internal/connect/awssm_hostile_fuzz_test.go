//go:build !noaws

package connect

// awssm_hostile_fuzz_test.go: FuzzAWSSMHostileEndpoint is the hostile-backend
// record-and-mutate target for the AWS Secrets Manager connector (rules:
// internal/fuzzutil/hostile/RULES.md). It builds a REAL secretsmanager.Client
// (smithy awsJson1_1 decode, SDK retryer and redirect policy) pointed at the
// harness through the connector's existing newClient seam, with static,
// non-functional credentials. Differences between the SDK's JSON decoder and
// the strict encoding/json decoder below are reported as such and classified
// SDK-BUG or EXPECTED during triage, never silently.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const (
	hostileAWSKeyID  = "AKIAHOSTILE00CANARY1"
	hostileAWSSecret = "hostileSecretAccessKeyCanary0123456789abcdefgh"
)

// strictAWSSecret: GetSecretValue returns SecretString (non-empty string) or
// SecretBinary (non-empty base64 blob); the connector returns the string, or
// the blob re-encoded as standard base64.
func strictAWSSecret(b []byte) (string, bool) {
	var d struct {
		SecretString *string `json:"SecretString"`
		SecretBinary []byte  `json:"SecretBinary"`
	}
	if json.Unmarshal(b, &d) != nil {
		return "", false
	}
	if d.SecretString != nil && *d.SecretString != "" {
		return *d.SecretString, true
	}
	if len(d.SecretBinary) > 0 {
		return base64.StdEncoding.EncodeToString(d.SecretBinary), true
	}
	return "", false
}

func FuzzAWSSMHostileEndpoint(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Ops: []hostile.Op{{Code: 0, A: 4}}}, {Ops: []hostile.Op{{Code: 1, A: 4}}}, {Ops: []hostile.Op{{Code: 11, A: 4}}},
		{Ops: []hostile.Op{{Code: 2, A: 4, B: 1}}}, {Ops: []hostile.Op{{Code: 3, A: 4, B: 0x81}}},
		{Ops: []hostile.Op{{Code: 6, A: 4, B: 8}}}, {Ops: []hostile.Op{{Code: 4, A: 4, B: 3}}},
		{Status: 10}, {Status: 16}, {Status: 8, Redir: 3}, {Redir: 1}, {Redir: 3}, {Redir: 5}, {Occ: 1, Redir: 2},
		{Frame: 1}, {Frame: 3}, {Fault: 2}, {Fault: 5}, {Enc: 2}, {Enc: 3}, {Trunc: 20},
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		h := runAWSSMHostile(hostile.Decode(prog), awssmKnown)
		defer h.Close()
		h.Finish(t.Fatalf)
	})
}

// awssmKnown lists this target's triaged, still-open findings (hostile.Known;
// issue-ready text in the m32 report). Each has a reproducer test below.
var awssmKnown = []hostile.Known{{
	// HARDENING: smithy's awsJson1_1 deserializer quotes the unexpected token
	// (`expected '{' ... got "<token>"`) and GetSecret wraps it with %w
	// (awssm.go, the GetSecretValue error). The text reaches the server log via
	// ReadFederatedSecret's log.Printf; the HTTP/gRPC response is clientSafe()d
	// and the audit row is generic. Only backend-chosen bytes are echoed.
	ID:          "HK-AWSSM-DESERIALIZE-ECHO",
	Class:       "HARDENING",
	Prefix:      `O7 LEAK: AWSSecretsManagerConnector.GetSecret: error text contains "` + hostile.Canary + `"`,
	ErrContains: "deserialization failed",
	// Input 828b725a61403e37: the whole 200 body is the canary JSON string.
	Repro: hostile.Program{Route: 48, Ops: []hostile.Op{{Code: 57}}},
}}

// runAWSSMHostile runs one program against the real SDK client and applies
// the target's oracles; the caller calls Finish (fuzz) or Evaluate (reproducer).
func runAWSSMHostile(p hostile.Program, known []hostile.Known) *hostile.Harness {
	h := hostile.New(hostile.Config{
		Routes: []hostile.Route{{Name: "sm", Method: "POST", Prefix: "/", Valid: func(int, *http.Request) hostile.Resp {
			return hostile.Resp{Status: 200, CT: "application/x-amz-json-1.1", Body: []byte(
				`{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:fuzz/secret-AbCdEf","Name":"fuzz/secret","VersionId":"v1","SecretString":"s3cr3t","VersionStages":["AWSCURRENT"],"CreatedDate":1.7E9}`)}
		}}},
		Program: p, Retries: true, // the SDK retryer re-sends failed exchanges; a success is judged on the last one
		Credentials: []string{hostileAWSKeyID, hostileAWSSecret}, RequestCeiling: 12,
		Known: known,
	})

	cl := secretsmanager.New(secretsmanager.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(hostileAWSKeyID, hostileAWSSecret, ""),
		BaseEndpoint: aws.String(h.URL()),
		// The same hardened client production installs (hardened_client.go).
		HTTPClient: &http.Client{Transport: newConnectHardenedTransport(awsBaseTransport()), CheckRedirect: refuseRedirect},
		Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = 3
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		}),
	})
	c := NewAWSSecretsManagerConnector("fuzz", "us-east-1", "", nil)
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

	var val string
	err := h.Run("AWSSecretsManagerConnector.GetSecret", func(ctx context.Context) error {
		var e error
		val, e = c.GetSecret(ctx, "fuzz/secret")
		return e
	})
	if p.Pristine() && (err != nil || val != "s3cr3t") {
		h.Violate("O6 LIVENESS: pristine GetSecret returned %q, %v (unmatched: %v)", val, err, h.Unmatched())
	}
	if err == nil {
		contentOK := func(b []byte) bool { _, ok := strictAWSSecret(b); return ok }
		body, kind := h.Delivery("sm", contentOK)
		// A final 2xx other than 200 is still O5/bad-status-accepted; when the
		// exchange is otherwise complete and every value check below passes it
		// carries the /2xx-valid-body sub-tag (the smithy client treats any 2xx as
		// success), so a known entry can name exactly that and nothing wider.
		other2xx := false
		if kind == "status" {
			if b2, k2 := h.Delivery("sm", contentOK, hostile.Status2xx...); k2 != "status" && k2 != "bad" {
				body, kind, other2xx = b2, k2, true
			}
		}
		want, ok := strictAWSSecret(body)
		valueOK := false
		switch {
		case kind == "status":
			h.Violate("O5/bad-status-accepted: GetSecret succeeded (%q) on a final HTTP status other than 200", val)
		case kind == "bad":
			h.Violate("O5/incomplete: GetSecret succeeded (%q) on an incomplete or redirected-away exchange", val)
		case hostile.HasDuplicateKeys(body):
			// duplicate member names: no single correct reading (RFC 8259)
		case !ok:
			h.Violate("O5/empty-or-invalid: GetSecret succeeded with %q but the strict decoder finds no non-empty SecretString/SecretBinary", val)
		case normUTF8(val) != want && val != want:
			h.Violate("O5/value: GetSecret returned %q, strict decoder %q", val, want)
		default:
			valueOK = true
		}
		if other2xx {
			if valueOK && kind == "" {
				h.Violate("O5/bad-status-accepted/2xx-valid-body: GetSecret succeeded (%q) on a final 2xx other than 200 with a complete body the strict decoder agrees with", val)
			} else {
				h.Violate("O5/bad-status-accepted: GetSecret succeeded (%q) on a final HTTP status other than 200", val)
			}
		}
		if kind == "transport" {
			h.Violate("O5/transport-error-ignored: GetSecret succeeded although the response ended in a transport/framing/gzip error")
		}
	}
	return h
}

// TestAWSSMHostileKnownFindingsReproduce replays every awssmKnown entry with
// the entry NOT applied; it goes red when a finding is fixed.
func TestAWSSMHostileKnownFindingsReproduce(t *testing.T) {
	for _, k := range awssmKnown {
		t.Run(k.ID, func(t *testing.T) {
			h := runAWSSMHostile(k.Repro, nil)
			defer h.Close()
			hostile.RequireKnownReproduces(t, k, h)
			for _, e := range h.Errors() {
				t.Logf("error text: %.300s", e)
			}
		})
	}
}

// normUTF8 applies encoding/json's treatment of invalid UTF-8 in a string (each
// bad byte becomes U+FFFD) so a decoder that passes raw bytes through is
// compared on content, not on that known difference.
func normUTF8(s string) string {
	b, _ := json.Marshal(s)
	var out string
	_ = json.Unmarshal(b, &out)
	return out
}
