package connect

// azurekv_response_fuzz_test.go — FuzzAzureKVConnectorResponse fuzzes what a
// hostile or broken Azure Key Vault endpoint sends back to
// AzureKeyVaultConnector.GetSecret.
//
// Existing tests (azurekv_test.go, connect_s2*_test.go) inject a hand-written
// azSecretGetter fake operating on already-decoded Go structs. This target instead
// builds a REAL azsecrets.Client pointed at an httptest.Server, injected through the
// existing c.newClient seam -- no production code change. Two SDK-specific wrinkles
// this needed to account for (both confirmed by reading the vendored SDK source, not
// assumed):
//
//   - azsecrets authenticates via a two-step "challenge" handshake
//     (KeyVaultChallengePolicy): the first request carries no Authorization header;
//     the server must answer 401 + WWW-Authenticate so the client learns the
//     scope/tenant, then retries WITH a bearer token attached. The fake server
//     below implements exactly that handshake (using the SAME shape the SDK's own
//     internal.FakeChallenge test helper produces) and only serves the fuzzed
//     status/body on the SECOND (authenticated) request -- verified against
//     policy_bearer_token.go's handleChallenge, which only re-triggers the
//     challenge flow on a 401 that ALSO carries a WWW-Authenticate header, so a
//     fuzzed 401 on the second response (no such header) cannot loop.
//   - azcore's BearerTokenPolicy refuses to attach a credential to a non-https
//     request by default (checkHTTPSForAuth). The obvious fix -- azcore.ClientOptions'
//     own InsecureAllowCredentialWithHTTP field -- does NOT work here: confirmed by
//     reading azsecrets' NewClient, it builds its OWN internal BearerTokenPolicy via
//     internal.NewKeyVaultChallengePolicy, which constructs a fresh
//     policy.BearerTokenOptions with no AllowHTTP wiring at all -- the top-level
//     ClientOptions field never reaches it, so setting it is a silent no-op (an
//     earlier version of this harness set it and every single execution failed at
//     this gate with a transport error, never reaching the fake server's response
//     logic at all -- caught only by adding a temporary diagnostic log, since none of
//     this harness's oracles are stated in the "must succeed" direction). The actual
//     fix: use a real httptest.NewTLSServer and srv.Client() as the Transport, so the
//     request genuinely is https and the gate passes on its own merits.
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// azureFuzzBearerToken is THE bearer token this target's fake credential actually
// sends -- not a response-body canary. Oracle (d) (RULES: "the backend auth
// token/credential the client SENT never appears in errors") is about this
// value, not response content; the fuzzed body is sent to the fake server
// byte-for-byte, unmodified, so azsecrets' JSON decode success path is actually
// reachable by the mutator (an earlier version of this harness prefixed a canary
// directly onto every response body, which corrupted JSON syntax on nearly every
// input and meant the success path was almost never reached).
const azureFuzzBearerToken = "fuzz-bearer-token-canary-c4e8"

// azureSecretValueRef is a minimal reference decode of the Key Vault secret
// bundle's wire shape (field name "value" confirmed against the vendored SDK's
// models_serde.go), used ONLY to derive whether the fuzzed body structurally
// carries a usable secret value -- so oracle (b) can assert the "no value"
// fail-closed path fires whenever it should, not just on a non-200 status.
type azureSecretValueRef struct {
	Value *string `json:"value"`
}

// fuzzAzureCred is a static azcore.TokenCredential -- GetToken always succeeds
// with a fixed token, so the harness exercises the connector's response handling,
// not azidentity's own credential-acquisition logic (out of scope here).
type fuzzAzureCred struct{}

func (fuzzAzureCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: azureFuzzBearerToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func FuzzAzureKVConnectorResponse(f *testing.F) {
	f.Add(200, []byte(`{"value":"s3cr3t","id":"https://v.vault.azure.net/secrets/db/abc123"}`))
	f.Add(404, []byte(`{"error":{"code":"SecretNotFound","message":"not found"}}`))
	f.Add(403, []byte(`{"error":{"code":"Forbidden","message":"denied"}}`))
	f.Add(500, []byte(``))
	f.Add(200, []byte(`not json`))
	f.Add(200, []byte(`{"value":null}`))
	f.Add(200, []byte(`{}`))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := clampHTTPStatus(status)

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				// Unauthenticated first request: elicit the challenge, same shape
				// azsecrets' own internal.FakeChallenge test helper produces.
				w.Header().Set("WWW-Authenticate", `Bearer authorization="https://fake.local/tenant" resource="https://vault.azure.net"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cl, err := azsecrets.NewClient(srv.URL, fuzzAzureCred{}, &azsecrets.ClientOptions{
			DisableChallengeResourceVerification: true,
			ClientOptions: azcore.ClientOptions{
				Transport: srv.Client(),
				Retry:     policy.RetryOptions{MaxRetries: -1},
			},
		})
		if err != nil {
			t.Fatalf("unexpected azsecrets.NewClient error: %v", err)
		}

		c := NewAzureKeyVaultConnector("fuzz", srv.URL, nil)
		c.newClient = func(_ context.Context) (azSecretGetter, error) { return cl, nil }

		var val string
		fuzzutil.Guard(t.Fatalf, "AzureKeyVaultConnector.GetSecret", func() {
			val, err = c.GetSecret(context.Background(), "fuzz-secret")
		})

		// Oracle (b): fail-closed, two ways --
		//  1. azsecrets.GetSecret requires EXACTLY 200 (runtime.HasStatusCode(
		//     httpResp, http.StatusOK)) -- any other status must error, never be
		//     treated as a successful read.
		//  2. a 200 response that structurally carries no non-null "value" field
		//     must ALSO error -- matches azurekv.go's own explicit "secret %q has
		//     no value" check.
		if code != http.StatusOK && err == nil {
			t.Fatalf("BYPASS: non-200 status %d treated as success, returned value %q", code, val)
		}
		var ref azureSecretValueRef
		hasValue := json.Unmarshal(body, &ref) == nil && ref.Value != nil
		if code == http.StatusOK && !hasValue && err == nil {
			t.Fatalf("BYPASS: response has no non-null value field but GetSecret returned success with value %q", val)
		}

		// Oracle (d): no credential echo. The bearer token the connector actually
		// sent must never appear in a returned error.
		if err != nil && strings.Contains(err.Error(), azureFuzzBearerToken) {
			t.Fatalf("LEAK: the connector's own bearer token appeared in a returned error: %v", err)
		}

		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after AzureKeyVaultConnector.GetSecret (expected O(10))", n)
		}
		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d open descriptors after AzureKeyVaultConnector.GetSecret (expected O(10))", fd)
		}
	})
}
