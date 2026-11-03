package dynamic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The minter's request errors are built by net/http from a URL that starts
// with the configured api_server. Go's *url.Error masks only a password, so a
// username-form credential or a query must be stripped before the error is
// returned, for a malformed host and for a transport failure alike.
func TestK8sMinterRequestErrors_CarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	srv := httptest.NewServer(http.NotFoundHandler())
	base, err := url.Parse(srv.URL)
	srv.Close()
	if err != nil {
		t.Fatal(err)
	}
	withUser := *base
	withUser.User = url.User(secret)
	withPassword := *base
	withPassword.User = url.UserPassword("admin", secret)
	hosts := map[string]string{
		"unparsable, password in port": "https://admin:" + secret + "/x@k8s.internal:6443",
		"transport error, username":    withUser.String(),
		"transport error, password":    withPassword.String(),
		"transport error, query":       base.String() + "/?token=" + secret,
	}
	calls := map[string]func(m *realK8sMinter) error{
		"mintToken": func(m *realK8sMinter) error {
			_, _, err := m.mintToken(context.Background(), "ns", "sa", nil, time.Hour, nil)
			return err
		},
		"createBoundSecret": func(m *realK8sMinter) error {
			_, err := m.createBoundSecret(context.Background(), "ns", "name")
			return err
		},
		"deleteBoundSecret": func(m *realK8sMinter) error {
			return m.deleteBoundSecret(context.Background(), "ns", "name")
		},
	}
	for hostName, host := range hosts {
		for callName, call := range calls {
			t.Run(callName+"/"+hostName, func(t *testing.T) {
				m := &realK8sMinter{host: host, token: "tok", hc: &http.Client{}}
				err := call(m)
				if err == nil {
					t.Fatalf("%s against %q = nil error, want an error", callName, host)
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
}
