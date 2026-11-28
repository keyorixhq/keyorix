package azuresource

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/keyorixhq/keyorix/migrate/internal/httpsafe"
)

// TestReadSecret_NonOKResponseDoesNotEchoBody: a vault, proxy or impersonating endpoint that
// answers GetSecret (or the list call) with a status other than 200 and the secret value in
// the body must not get that value into List's error. azcore's ResponseError text prints the
// whole body, so before the fix the value appeared verbatim (found by
// FuzzAzureSourceHostileEndpoint, seed 552c14b2e113ee80). Each case runs twice: through a
// plain transport, which proves the status-only error in azure.go on its own, and through
// httpsafe.NewAzureClient, the production stack whose body scrub is the second layer.
func TestReadSecret_NonOKResponseDoesNotEchoBody(t *testing.T) {
	const listBody = `{"value":[{"id":"https://vault.azure.net/secrets/db","attributes":{"enabled":true}}]}`
	secretBody := `{"value":"` + azValueCanary + `","id":"https://vault.azure.net/secrets/db/v1"}`
	cases := []struct {
		name       string
		listStatus int
		getStatus  int
		wantErr    string
	}{
		{"get 403 echoing the secret", 200, http.StatusForbidden, `get "db": unexpected status 403`},
		{"get 500 echoing the secret", 200, http.StatusInternalServerError, `get "db": unexpected status 500`},
		{"get 203 from a proxy carrying the real body", 200, http.StatusNonAuthoritativeInfo, `get "db": unexpected status 203`},
		{"get 206 from a proxy carrying the real body", 200, http.StatusPartialContent, `get "db": unexpected status 206`},
		{"list 403 echoing the secret", http.StatusForbidden, 200, `list secrets: unexpected status 403`},
	}
	transports := []struct {
		name string
		mk   func(*tls.Config) *http.Client
	}{
		{"plain", func(tc *tls.Config) *http.Client {
			return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		}},
		{"httpsafe.NewAzureClient", func(tc *tls.Config) *http.Client {
			return httpsafe.NewAzureClient(&http.Transport{TLSClientConfig: tc})
		}},
	}
	for _, tc := range cases {
		for _, tr := range transports {
			t.Run(tc.name+"/"+tr.name, func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("x-ms-error-code", azValueCanary)
					if strings.TrimSuffix(r.URL.Path, "/") == "/secrets" {
						w.WriteHeader(tc.listStatus)
						if tc.listStatus == 200 {
							_, _ = fmt.Fprint(w, listBody)
						} else {
							_, _ = fmt.Fprint(w, secretBody)
						}
						return
					}
					w.WriteHeader(tc.getStatus)
					_, _ = fmt.Fprint(w, secretBody)
				}))
				defer srv.Close()

				tlsCfg := &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
				cl, err := azsecrets.NewClient(srv.URL, azFakeCred{}, &azsecrets.ClientOptions{
					ClientOptions: azcore.ClientOptions{
						Transport: tr.mk(tlsCfg),
						Retry:     policy.RetryOptions{MaxRetries: -1},
					},
				})
				if err != nil {
					t.Fatalf("azsecrets.NewClient: %v", err)
				}
				c := New(Config{VaultURL: srv.URL})
				c.newClient = func(context.Context) (azAPI, error) { return cl, nil }

				_, _, err = c.List(context.Background())
				if err == nil {
					t.Fatalf("List succeeded, want an error for status list=%d get=%d", tc.listStatus, tc.getStatus)
				}
				if strings.Contains(err.Error(), azValueCanary) {
					t.Fatalf("List error echoes the secret value: %v", err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("List error = %q, want it to contain %q", err, tc.wantErr)
				}
			})
		}
	}
}

// TestList_NamelessListedIDIsReported: a listed ID without a name is reported as Skipped, not
// dropped, matching List's "report, don't drop" contract.
func TestList_NamelessListedIDIsReported(t *testing.T) {
	empty := azsecrets.ID("")
	f := &fakeAz{
		pages: [][]*azsecrets.SecretProperties{{{ID: &empty, Attributes: enabled(true)}}},
	}
	entries, skipped, err := newClientWithFake(f).List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 || len(f.getCalls) != 0 {
		t.Fatalf("entries = %+v, getCalls = %v, want none", entries, f.getCalls)
	}
	if len(skipped) != 1 || skipped[0].Reason != "listed secret ID has no name" ||
		skipped[0].Locator != "azure-key-vault:https://fake.vault.azure.net/<unnamed>" {
		t.Fatalf("skipped = %+v, want one nameless-ID entry", skipped)
	}
}
