package azuresource

// azure_hostile_fuzz_test.go: FuzzAzureSourceHostileEndpoint drives the REAL
// azsecrets.Client (via the newClient hook pointing it at a TLS httptest server) through
// azuresource.Client.List. The harness is TLS because the production VaultURL is HTTPS;
// a fake StaticTokenCredential satisfies azcore.TokenCredential with no real Azure identity
// chain or network calls, matching internal/connect/azurekv.go's test precedent.
//
// Oracles (what each does NOT verify):
//   - O1 NO-PANIC / O2 NO-HANG / O4 BOUNDED-WORK: via hostile.Harness.Run around List.
//   - O6 LIVENESS: pristine program returns exactly the one planted secret (value = azValueCanary).
//   - VALUE-LEAK: azValueCanary must never appear in List's error or captured slog logs.
//     Does NOT scan the eventual report rendering (covered by cmd-level targets if added).
//   - O9 SSRF: sentinel internal-address server receives zero requests (httpsafe refuses redirects).
//   - O7 (echo class suppressed via KX_HOSTILE_ALLOW=O7): the Azure SDK may echo mutated
//     response bodies in deserialization errors, which is the echo class (server-controlled
//     response TEXT in an error), not a secret VALUE leak per the brief's own rule. The real
//     VALUE-LEAK check above is kept live separately.
//   - SplitJSON path: not exercised; the pristine value is a plain string, not a JSON object.
//   - Multi-page list pagination: single-page pristine only; the hostile mutation applies to one
//     route occurrence, not a multi-page sequence.
//   - Disabled-secret and nil-ID skip paths: not fuzzed; the valid list response always returns
//     enabled:true with a non-empty id.
//
// FINDING F1 (fixed in this change, see TestListedSecretName_MalformedServerIDs): a hostile
// server returning an empty or one-segment secret ID made azsecrets.ID.Name() dereference a
// nil pointer. The two seeds below reproduce it end to end through the real client and stay
// as regression seeds.

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/keyorixhq/keyorix/migrate/internal/hostile"
	"github.com/keyorixhq/keyorix/migrate/internal/httpsafe"
)

// azValueCanary is the secret VALUE (must never appear in List's error or log). Distinct from
// hostile.Canary so a mutation-injected hostile.Canary echoed by the Azure SDK decoder is not
// conflated with a real secret-value leak. Same pattern as awssource's awsValueCanary.
const azValueCanary = "kx-azure-value-canary-8e2f"

// azFakeCred satisfies azcore.TokenCredential with a static bearer token. No Azure identity
// chain or token-endpoint network calls happen during the fuzz run.
type azFakeCred struct{}

func (azFakeCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     "kx-azure-fake-token-9d3c",
		ExpiresOn: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

// azHostileRoutes serves two Azure Key Vault REST routes:
//   - "list" (GET /secrets): a one-page list response with no nextLink (pager terminates).
//   - "get"  (GET /secrets/db): GetSecret response whose value is the azValueCanary.
//
// The id field in the list response uses a fixed vault hostname so that
// internal/ParseID splits the path as ["secrets","db"] and returns Name()=="db".
// The Azure SDK then calls GET {vaultURL}/secrets/db which matches the more-specific "get"
// prefix over the "list" prefix (longest prefix wins in hostile.Harness).
func azHostileRoutes() []hostile.Route {
	js := func(s string) hostile.Resp {
		return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)}
	}
	return []hostile.Route{
		{Name: "list", Method: "GET", Prefix: "/secrets", Valid: func(int, *http.Request) hostile.Resp {
			// nextLink absent: pager.More() = false after this page, no additional list requests.
			return js(`{"value":[{"id":"https://vault.azure.net/secrets/db","attributes":{"enabled":true,"created":1748304000,"updated":1748304000}}]}`)
		}},
		{Name: "get", Method: "GET", Prefix: "/secrets/db", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"value":"` + azValueCanary + `","id":"https://vault.azure.net/secrets/db/v1","attributes":{"enabled":true,"created":1748304000,"updated":1748304000}}`)
		}},
	}
}

// azHostileClient builds a real azsecrets.Client aimed at the hostile server. The transport
// wraps httpsafe.CappedTransport around a TLS config that trusts the harness's self-signed
// certificate. RetryOptions.MaxRetries=0 makes request counts deterministic.
func azHostileClient(h *hostile.Harness) (azAPI, error) {
	transport := httpsafe.CappedTransport{Base: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.CertPool()},
	}}
	httpClient := &http.Client{
		Timeout:       httpsafe.ClientTimeout,
		Transport:     transport,
		CheckRedirect: httpsafe.RefuseRedirect,
	}
	return azsecrets.NewClient(h.URL(), azFakeCred{}, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient,
			Retry:     policy.RetryOptions{MaxRetries: 0},
		},
	})
}

func FuzzAzureSourceHostileEndpoint(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Route: 0, Ops: []hostile.Op{{Code: 1, A: 1}}},        // list: delete a field
		{Route: 0, Ops: []hostile.Op{{Code: 7, A: 1, B: 2}}},  // list: oversized value array
		{Route: 0, Ops: []hostile.Op{{Code: 6, A: 3, B: 0}}},  // list: id -> "" (nil-name panic before the fix)
		{Route: 0, Ops: []hostile.Op{{Code: 12, A: 3}}},       // list: id -> canary, one segment (same panic)
		{Route: 0, Ops: []hostile.Op{{Code: 6, A: 3, B: 11}}}, // list: id -> path traversal (4 segs)
		{Route: 1, Ops: []hostile.Op{{Code: 1, A: 1}}},        // get: delete value field
		{Route: 1, Ops: []hostile.Op{{Code: 4, A: 1, B: 2}}},  // get: huge value string
		{Route: 1, Ops: []hostile.Op{{Code: 12, A: 1}}},       // get: value -> canary
		{Route: 0, Frame: 3},                                  // list: truncated body (cl-too-short)
		{Route: 1, Frame: 3},                                  // get: truncated body
		{Route: 1, Fault: 2},                                  // get: rst-mid-body
		{Route: 1, Enc: 2},                                    // get: gzip bomb
		{Route: 1, Status: 16},                                // get: 500 on everything
		{Route: 0, Redir: 1},                                  // list: redirect to attacker (SSRF sentinel)
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes:  azHostileRoutes(),
			Program: p,
			TLS:     true,
			// SDK retries are disabled (MaxRetries=0), so the only source of multiple
			// requests is the one-get-per-listed-item pattern: 1 ListSecrets + N GetSecret
			// (N = items in the list response). The hostile oversized-list mutation can produce
			// up to listSizes[2]=60,000 items; ceiling of 65,000 covers that while still
			// catching a genuine SDK retry storm. O2 (hang) bounds the absolute wall-clock
			// for very large N.
			RequestCeiling: 65000,
			Retries:        false,
		})
		defer h.Close()

		cl, err := azHostileClient(h)
		if err != nil {
			return // client construction failure is a harness-setup issue, not a finding
		}
		c := New(Config{VaultURL: h.URL()})
		c.newClient = func(context.Context) (azAPI, error) { return cl, nil }

		var entries []azHE
		errList := h.Run("azuresource.List", func(ctx context.Context) error {
			es, _, err := c.List(ctx)
			for _, e := range es {
				entries = append(entries, azHE{e.RawName, e.Value})
			}
			return err
		})

		// VALUE-LEAK: the secret value canary must never appear in the error or captured logs.
		// KX_HOSTILE_ALLOW=O7 suppresses the generic field-echo class (Azure SDK may echo
		// mutated body text in deserialization errors — that is echo-class, not value-leak).
		scan := ""
		if errList != nil {
			scan = errList.Error()
		}
		scan += "\n" + h.Logs()
		if strings.Contains(scan, azValueCanary) {
			h.Violate("VALUE-LEAK: the Azure secret value appears in azuresource.List error or log")
		}

		// O6 LIVENESS: pristine program must return exactly the planted secret.
		if p.Pristine() {
			if errList != nil {
				h.Violate("O6 LIVENESS: pristine List errored: %v (unmatched: %v)", errList, h.Unmatched())
			} else if len(entries) != 1 || entries[0].name != "db" || entries[0].value != azValueCanary {
				h.Violate("O6 LIVENESS: pristine List returned %#v (want one db=%s)", entries, azValueCanary)
			}
		}
		if h.AttackerHits() > 0 {
			h.Violate("SSRF: azuresource sent %d request(s) to the sentinel internal address", h.AttackerHits())
		}

		h.Finish(t.Fatalf)
	})
}

// azHE pairs a raw name with its value for the LIVENESS check.
type azHE struct{ name, value string }
