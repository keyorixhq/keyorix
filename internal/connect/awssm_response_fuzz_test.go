package connect

// awssm_response_fuzz_test.go — FuzzAWSSMConnectorResponse fuzzes what a hostile
// or broken AWS Secrets Manager endpoint sends back to
// AWSSecretsManagerConnector.GetSecret.
//
// Existing tests (awssm_test.go, connect_s2*_test.go) inject a hand-written
// smSecretGetter fake operating on already-decoded Go structs -- that bypasses the
// AWS SDK's own JSON wire decode entirely. This target instead builds a REAL
// secretsmanager.Client pointed at an httptest.Server via the SDK's BaseEndpoint
// option (with static, non-functional credentials and retries disabled), injected
// through the existing c.newClient test seam -- no production code change. This
// exercises the actual smithy-go awsJson1_1 protocol decode, not just the
// connector's own post-decode field checks.
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// awsFuzzAccessKeyID/awsFuzzSecretKey are THE static credentials this target's
// client actually sends -- not response-body canaries. Oracle (d) (RULES: "the
// backend auth token/credential the client SENT never appears in errors") is
// about these values, not response content; the fuzzed body is sent to the fake
// server byte-for-byte, unmodified, so the smithy-go JSON decode success path is
// actually reachable by the mutator (an earlier version of this harness prefixed
// a canary directly onto every response body, which corrupted JSON syntax on
// nearly every input and meant the success path was almost never reached).
const (
	awsFuzzAccessKeyID = "AKIAFUZZCANARY7E91XY"
	awsFuzzSecretKey   = "fuzzSecretAccessKeyCanary7e91xyfuzzSecretKey"
)

// awsAccessSecretValueRef is a minimal reference decode of GetSecretValueOutput's
// wire shape (field names/types confirmed against the vendored SDK's
// deserializers.go), used ONLY to derive whether the fuzzed body structurally
// carries a usable secret value -- so oracle (b) can assert the "no value"
// fail-closed path fires whenever it should, not just on a non-2xx status.
type awsAccessSecretValueRef struct {
	SecretString *string `json:"SecretString"`
	SecretBinary []byte  `json:"SecretBinary"`
}

func FuzzAWSSMConnectorResponse(f *testing.F) {
	f.Add(200, []byte(`{"SecretString":"s3cr3t"}`))
	f.Add(200, []byte(`{"SecretBinary":"AAEC"}`))
	f.Add(200, []byte(`{}`))
	f.Add(400, []byte(`{"__type":"ResourceNotFoundException","Message":"Secrets Manager can't find the specified secret."}`))
	f.Add(403, []byte(`{"__type":"AccessDeniedException","Message":"denied"}`))
	f.Add(500, []byte(``))
	f.Add(200, []byte(`not json`))
	f.Add(200, []byte(`{"SecretString":null,"SecretBinary":null}`))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := clampHTTPStatus(status)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cl := secretsmanager.New(secretsmanager.Options{
			Region:           "us-east-1",
			Credentials:      credentials.NewStaticCredentialsProvider(awsFuzzAccessKeyID, awsFuzzSecretKey, ""),
			BaseEndpoint:     aws.String(srv.URL),
			RetryMaxAttempts: 1,
		})

		c := NewAWSSecretsManagerConnector("fuzz", "us-east-1", "", nil)
		c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

		var val string
		var err error
		fuzzutil.Guard(t.Fatalf, "AWSSecretsManagerConnector.GetSecret", func() {
			val, err = c.GetSecret(context.Background(), "fuzz/secret")
		})

		// Oracle (b): fail-closed, two ways --
		//  1. the smithy-go awsJson1_1 deserializer routes any response outside
		//     [200,300) to the error deserializer -- GetSecret must therefore
		//     error, never return a value, on such a status.
		//  2. a 2xx response that structurally carries neither a SecretString nor
		//     a non-empty SecretBinary must ALSO error -- matches awssm.go's own
		//     explicit "secret %q has no value" fallback.
		if (code < 200 || code >= 300) && err == nil {
			t.Fatalf("BYPASS: status %d outside [200,300) treated as success, returned value %q", code, val)
		}
		var ref awsAccessSecretValueRef
		hasValue := json.Unmarshal(body, &ref) == nil && (ref.SecretString != nil || len(ref.SecretBinary) > 0)
		if code >= 200 && code < 300 && !hasValue && err == nil {
			t.Fatalf("BYPASS: response has no SecretString/SecretBinary field but GetSecret returned success with value %q", val)
		}

		// Oracle (d): no credential echo. The access key ID the connector actually
		// sent (in the SigV4 Authorization header) must never appear in a
		// returned error.
		if err != nil && strings.Contains(err.Error(), awsFuzzAccessKeyID) {
			t.Fatalf("LEAK: the connector's own AWS access key ID appeared in a returned error: %v", err)
		}

		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after AWSSecretsManagerConnector.GetSecret (expected O(10))", n)
		}
		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d open descriptors after AWSSecretsManagerConnector.GetSecret (expected O(10))", fd)
		}
	})
}
