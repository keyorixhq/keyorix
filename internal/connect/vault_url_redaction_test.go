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

// closedServerURL returns the base URL of an httptest server that has already
// been shut down, so every request to it fails at the transport layer and the
// connector returns the *url.Error the HTTP client built from the full URL.
func closedServerURL(t *testing.T) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u, err := url.Parse(srv.URL)
	srv.Close()
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// assertNoVaultCredentials fails when msg echoes any part of the configured
// address's userinfo or query.
func assertNoVaultCredentials(t *testing.T, msg, secret string) {
	t.Helper()
	for _, leaked := range []string{secret, "admin", "token=", "?"} {
		if strings.Contains(msg, leaked) {
			t.Errorf("error %q contains %q", msg, leaked)
		}
	}
}

// CheckTokenTTL runs at boot (server/wire_connect.go) without validating the
// address first and its error is logged, so neither a malformed address nor a
// transport failure may echo the configured address's userinfo or query. Go's
// *url.Error masks only a password, never a username-form token or ?token=.
func TestVaultCheckTokenTTL_ErrorsCarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	base := closedServerURL(t)
	withUser := *base
	withUser.User = url.User(secret)
	withPassword := *base
	withPassword.User = url.UserPassword("admin", secret)
	cases := map[string]string{
		"unparsable, password in port": "https://admin:" + secret + "/x@vault.internal:8200",
		"transport error, username":    withUser.String(),
		"transport error, password":    withPassword.String(),
		"transport error, query":       base.String() + "/?token=" + secret,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			c := NewVaultConnector("v", addr, "tok", nil)
			_, _, err := c.CheckTokenTTL(context.Background())
			if err == nil {
				t.Fatalf("CheckTokenTTL(%q) = nil error, want an error", addr)
			}
			assertNoVaultCredentials(t, err.Error(), secret)
		})
	}
}

// GetSecret's transport errors (the mount-info lookup and the secret read) are
// logged by internal/core/connect.go, so they must not echo the configured
// address's userinfo or query either.
func TestVaultGetSecret_TransportErrorsCarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	t.Run("mount-info lookup", func(t *testing.T) {
		base := closedServerURL(t)
		withUser := *base
		withUser.User = url.User(secret)
		for name, addr := range map[string]string{
			"username": withUser.String(),
			"query":    base.String() + "/?token=" + secret,
		} {
			t.Run(name, func(t *testing.T) {
				c := NewVaultConnector("v", addr, "tok", nil)
				_, err := c.GetSecret(context.Background(), "secret/data/x")
				if err == nil {
					t.Fatal("GetSecret against a closed server = nil error, want an error")
				}
				if !strings.Contains(err.Error(), "mount version") {
					t.Fatalf("error %q is not the mount-info path under test", err)
				}
				assertNoVaultCredentials(t, err.Error(), secret)
			})
		}
	})
	t.Run("secret read", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
				_, _ = w.Write([]byte(vaultMountInfoV2()))
				return
			}
			// Drop the connection without a response: the client sees a
			// transport error on the secret read itself.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("response writer is not a Hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}))
		t.Cleanup(srv.Close)
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.User(secret)
		c := NewVaultConnector("v", u.String(), "tok", nil)
		_, err = c.GetSecret(context.Background(), "secret/data/x")
		if err == nil {
			t.Fatal("GetSecret with a dropped connection = nil error, want an error")
		}
		if !strings.Contains(err.Error(), "vault: get ") {
			t.Fatalf("error %q is not the secret-read path under test", err)
		}
		assertNoVaultCredentials(t, err.Error(), secret)
	})
}
