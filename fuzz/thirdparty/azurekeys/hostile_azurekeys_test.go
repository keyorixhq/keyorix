// Hostile-SERVER fuzz harness for
// github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys, the SDK Keyorix
// uses as its Azure Key Vault KMS provider (internal/crypto/azurekms): WrapKey
// wraps the data-encryption key at first run, UnwrapKey unwraps it on every
// secret read. The vault URL comes from kms_key_id, an operator-configured key
// identifier URL.
//
// Threat model: an on-path attacker MITMs the Key Vault endpoint (or the operator
// pointed kms_key_id at a hostile host that nonetheless passed the static
// host-suffix allowlist) and replies with hostile JSON — wrong content-type,
// truncated/garbage JSON, missing fields, deeply nested JSON, a wrong/absent KID.
// This harness drives a REAL azkeys.Client (constructed as azurekms.New does,
// azkeys.NewClient with a transport override) against an httptest TLS server
// whose status and body are fuzzer-controlled, with a FAKE TokenCredential that
// hands out a BEARER-TOKEN CANARY (azcore's bearer policy refuses to attach a
// token over plaintext http, so a TLS server is required for the request to reach
// the JSON decode path at all), and calls WrapKey and UnwrapKey.
//
// Oracles (sound only):
//   - Panic: no panic escapes the SDK's documented error return (RunGuarded).
//   - Bounded time: each call returns within the guard deadline even against a
//     huge/deeply-nested body (azcore retries bounded to MaxRetries, tiny delay).
//   - No goroutine / fd leak after the calls return (CheckNoLeak).
//   - Fail-closed on non-2xx: azcore routes any status outside the success set to
//     an *azcore.ResponseError, so WrapKey/UnwrapKey MUST return an error on such
//     a status (never a populated response).
//   - No retry storm: the fake endpoint is hit at most azRetryCeiling times per op.
//   - Credential confidentiality: the bearer-token canary must never appear in a
//     returned error (AssertNoSecretInError).
//
// What these oracles do NOT verify (stated, per the method):
//   - NOT the cross-host-redirect SSRF guard. Production relies on
//     azurekms.azureKMSTransport's DIAL-TIME IsPrivateOrLinkLocal check (not on
//     CheckRedirect) to stop the live bearer token reaching an attacker host; this
//     target uses the httptest server's own client transport and therefore does
//     NOT replicate that guard — redirect-following behaviour is out of scope here
//     and is covered by azurekms's own transport tests.
//   - NOT the envelope MAC / version-pinning correctness (azurekms.go's encode/
//     decodeEnvelope and versionMAC) — that is a Keyorix-layer property with its
//     own unit tests, not an SDK-decode property.
//   - NOT credentials from DefaultAzureCredential (a fake credential is injected,
//     so no real Azure AD token endpoint is ever contacted).
package azurekeyshostile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/cloudfuzz"
)

// azBearerCanary is the bearer token this harness's fake credential hands out —
// the value the credential-confidentiality oracle scans error strings for.
const azBearerCanary = "az-bearer-token-CANARY-7e91xy-must-never-leak"

const azRetryCeiling = 10

// fakeCred is an azcore.TokenCredential that always returns the canary bearer
// token, so no real Azure AD endpoint is contacted and the token value is known
// for the leak oracle.
type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: azBearerCanary, ExpiresOn: farFuture()}, nil
}

func farFuture() time.Time { return time.Unix(1<<40, 0) }

func FuzzAzureKeysResponse(f *testing.F) {
	f.Add(200, []byte(`{"kid":"https://v.vault.azure.net/keys/k/abc","value":"d3JhcHBlZA"}`)) // WrapKey-shaped
	f.Add(200, []byte(`{"value":"dW53cmFwcGVk"}`))                                            // UnwrapKey-shaped
	f.Add(200, []byte(`{}`))
	f.Add(400, []byte(`{"error":{"code":"BadParameter","message":"x"}}`))
	f.Add(401, []byte(`{"error":{"code":"Unauthorized"}}`))
	f.Add(403, []byte(`{"error":{"code":"Forbidden"}}`))
	f.Add(500, []byte(``))
	f.Add(200, []byte(`not json`))
	f.Add(200, []byte(`{"value":`))        // truncated
	f.Add(200, []byte(`{"value":12345}`))  // wrong type
	f.Add(429, []byte(`{"error":{"code":"TooManyRequests"}}`))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := cloudfuzz.ClampHTTPStatus(status)

		var hits atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cl, err := azkeys.NewClient(srv.URL, fakeCred{}, &azkeys.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Transport: srv.Client(),
				Retry: policy.RetryOptions{
					MaxRetries:    2,
					RetryDelay:    time.Millisecond,
					TryTimeout:    2 * time.Second,
					MaxRetryDelay: 5 * time.Millisecond,
				},
			},
		})
		if err != nil {
			t.Fatalf("harness bug: azkeys.NewClient: %v", err)
		}

		params := azkeys.KeyOperationParameters{
			Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
			Value:     []byte("kek-material-32-bytes-padding-xxx"),
		}

		type opCall struct {
			name string
			run  func(context.Context) error
		}
		ops := []opCall{
			{"WrapKey", func(ctx context.Context) error {
				_, e := cl.WrapKey(ctx, "fuzzkey", "", params, nil)
				return e
			}},
			{"UnwrapKey", func(ctx context.Context) error {
				_, e := cl.UnwrapKey(ctx, "fuzzkey", "", params, nil)
				return e
			}},
		}

		for _, op := range ops {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			hits.Store(0)
			var oerr error
			cloudfuzz.RunGuarded(t, "azkeys."+op.name, func() {
				oerr = op.run(ctx)
			})
			cancel()

			if (code < 200 || code >= 300) && oerr == nil {
				t.Fatalf("BYPASS: azkeys.%s treated non-2xx status %d as success", op.name, code)
			}
			cloudfuzz.AssertNoSecretInError(t, "azkeys."+op.name, oerr, azBearerCanary)
			if h := hits.Load(); h > azRetryCeiling {
				t.Fatalf("RETRY STORM: azkeys.%s hit the fake endpoint %d times (MaxRetries=2)", op.name, h)
			}
		}

		cloudfuzz.CheckNoLeak(t, "azkeys response fuzz")
	})
}
