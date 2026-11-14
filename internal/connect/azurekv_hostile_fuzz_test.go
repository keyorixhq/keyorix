//go:build !noazure

package connect

// azurekv_hostile_fuzz_test.go: FuzzAzureKVHostileEndpoint is the hostile-backend
// record-and-mutate target for the Azure Key Vault connector (rules: internal/
// fuzzutil/hostile/RULES.md). It builds a REAL azsecrets client with the same
// hardened transport production installs (azureBaseTransport wrapped by
// newAzureHardenedTransport, redirects refused), trusting only the harness's
// TLS certificate, and answers the SDK's bearer-challenge handshake with a
// pristine 401 that the mutation program never touches (Route.Pass).

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const hostileAzureBearer = "kx-hostile-azure-bearer-c4e8"

type hostileAzureCred struct{}

func (hostileAzureCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: hostileAzureBearer, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// strictAzureSecret: Key Vault "Get Secret" returns {"value": "<string>", ...};
// an absent, null or empty value is not a secret. Member names are matched
// exactly (RFC 8259 names are case-sensitive): encoding/json's struct decoding
// folds case, which would let a {"value":"x","VALUE":null} body read as "no
// value" while the SDK, which looks the member up by its exact name, reads "x".
func strictAzureSecret(b []byte) (string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return "", false
	}
	raw, ok := m["value"]
	if !ok {
		return "", false
	}
	var v *string
	if json.Unmarshal(raw, &v) != nil || v == nil || *v == "" {
		return "", false
	}
	return *v, true
}

func FuzzAzureKVHostileEndpoint(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Ops: []hostile.Op{{Code: 0, A: 1}}}, {Ops: []hostile.Op{{Code: 1, A: 1}}}, {Ops: []hostile.Op{{Code: 11, A: 1}}},
		{Ops: []hostile.Op{{Code: 2, A: 1, B: 1}}}, {Ops: []hostile.Op{{Code: 6, A: 1, B: 8}}}, {Ops: []hostile.Op{{Code: 4, A: 1, B: 3}}},
		{Status: 10}, {Status: 16}, {Redir: 1}, {Redir: 3}, {Occ: 1, Redir: 2},
		{Fault: 2}, {Fault: 5}, {Fault: 7}, {Enc: 2}, {Enc: 3}, {Frame: 2}, {Trunc: 20},
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: []hostile.Route{{
				Name: "secret", Method: "GET", Prefix: "/secrets/",
				Pass: func(r *http.Request) (hostile.Resp, bool) {
					if r.Header.Get("Authorization") != "" {
						return hostile.Resp{}, false
					}
					return hostile.Resp{Status: 401, CT: "application/json", Body: []byte(`{"error":{"code":"Unauthorized"}}`),
						Headers: [][2]string{{"WWW-Authenticate", `Bearer authorization="https://login.example.test/tenant" resource="https://vault.azure.net"`}}}, true
				},
				Valid: func(int, *http.Request) hostile.Resp {
					return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(
						`{"value":"s3cr3t","id":"https://v.vault.azure.net/secrets/fuzz-secret/abc123","attributes":{"enabled":true,"created":1700000000}}`)}
				},
			}},
			Program: p, TLS: true, Retries: true,
			Credentials: []string{hostileAzureBearer}, RequestCeiling: 8,
		})
		defer h.Close()

		tr := azureBaseTransport()
		tr.TLSClientConfig.RootCAs = h.CertPool()
		cl, err := azsecrets.NewClient(h.URL(), hostileAzureCred{}, &azsecrets.ClientOptions{
			DisableChallengeResourceVerification: true,
			ClientOptions: azcore.ClientOptions{
				Transport: &http.Client{Transport: newAzureHardenedTransport(tr), CheckRedirect: refuseRedirect},
				Retry:     policy.RetryOptions{MaxRetries: 2, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond},
			},
		})
		if err != nil {
			t.Fatalf("azsecrets.NewClient: %v", err)
		}
		c := NewAzureKeyVaultConnector("fuzz", h.URL(), nil)
		c.newClient = func(_ context.Context) (azSecretGetter, error) { return cl, nil }

		var val string
		gerr := h.Run("AzureKeyVaultConnector.GetSecret", func(ctx context.Context) error {
			var e error
			val, e = c.GetSecret(ctx, "fuzz-secret")
			return e
		})
		if p.Pristine() && (gerr != nil || val != "s3cr3t") {
			h.Violate("O6 LIVENESS: pristine GetSecret returned %q, %v (unmatched: %v)", val, gerr, h.Unmatched())
		}
		if gerr == nil {
			body, kind := h.Delivery("secret", func(b []byte) bool { _, ok := strictAzureSecret(b); return ok })
			want, ok := strictAzureSecret(body)
			switch {
			case kind == "status":
				h.Violate("O5/bad-status-accepted: GetSecret succeeded (%q) on a final HTTP status other than 200", val)
			case kind == "bad":
				h.Violate("O5/incomplete: GetSecret succeeded (%q) on an incomplete or redirected exchange", val)
			case hostile.HasDuplicateKeys(body):
				// duplicate member names: no single correct reading (RFC 8259)
			case !ok:
				h.Violate("O5/empty-or-invalid: GetSecret succeeded with %q but the delivered body has no non-empty value", val)
			case normUTF8(val) != want && val != want:
				h.Violate("O5/value: GetSecret returned %q, strict decoder %q", val, want)
			}
			if kind == "transport" {
				h.Violate("O5/transport-error-ignored: GetSecret succeeded although the response ended in a transport/framing/gzip error")
			}
		}
		h.Finish(t.Fatalf)
	})
}
