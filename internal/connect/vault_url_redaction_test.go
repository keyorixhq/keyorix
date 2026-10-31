package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A configured Vault address can carry userinfo or a ?token= query; the
// validation errors name the destination, so they must never echo either.
func TestValidateConnectorURL_ErrorsCarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	cases := map[string]string{
		"bad scheme with userinfo and query": "ftp://admin:" + secret + "@vault.internal:8200/v1?token=" + secret,
		"missing host with query":            "https:///v1?token=" + secret,
		"unparsable, password in port":       "https://admin:" + secret + "/x@vault.internal:8200",
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateConnectorURL(addr)
			if err == nil {
				t.Fatalf("validateConnectorURL(%q) = nil, want an error", addr)
			}
			msg := err.Error()
			for _, leaked := range []string{secret, "admin", "token=", "?"} {
				if strings.Contains(msg, leaked) {
					t.Errorf("error %q contains %q", msg, leaked)
				}
			}
		})
	}
}

// The link-local refusal names the address it refused; it runs on every
// GetSecret (Vault) and for Azure Key Vault, so it must not echo userinfo or a
// query either.
func TestValidateConnectorAddressNotLinkLocal_ErrorCarriesNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	addr := "http://admin:" + secret + "@169.254.169.254:8200/v1?token=" + secret
	err := validateConnectorAddressNotLinkLocal("vault", addr)
	if err == nil {
		t.Fatalf("validateConnectorAddressNotLinkLocal(%q) = nil, want an error", addr)
	}
	msg := err.Error()
	if !strings.Contains(msg, "link-local") {
		t.Errorf("error %q no longer says link-local", msg)
	}
	for _, leaked := range []string{secret, "admin", "token=", "?"} {
		if strings.Contains(msg, leaked) {
			t.Errorf("error %q contains %q", msg, leaked)
		}
	}
}

// A non-200 from Vault is the most common GetSecret failure (a 403 for a
// token without the policy, a 404 for a missing path), and its error is
// logged server-side, so it must not echo the configured address's userinfo.
func TestVaultGetSecret_Non200ErrorCarriesNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
			_, _ = w.Write([]byte(vaultMountInfoV2()))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("admin", secret)

	c := NewVaultConnector("v", u.String(), "tok", nil)
	_, err = c.GetSecret(context.Background(), "secret/data/x")
	if err == nil {
		t.Fatal("GetSecret against a 403 = nil error, want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "HTTP 403") {
		t.Fatalf("error %q is not the non-200 path under test", msg)
	}
	for _, leaked := range []string{secret, "admin"} {
		if strings.Contains(msg, leaked) {
			t.Errorf("error %q contains %q", msg, leaked)
		}
	}
}
