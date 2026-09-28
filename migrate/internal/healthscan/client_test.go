package healthscan

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// spyTransport fails the test the instant any request reaches it — used to prove a rejected
// method never gets far enough to attempt network I/O.
type spyTransport struct{ t *testing.T }

func (s spyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.t.Fatalf("network I/O attempted for a request that should have been rejected before any request was built: %s %s", req.Method, req.URL)
	return nil, nil
}

// TestRequest_RejectsWriteMethods is the red/green proof for G1's core guarantee: this client
// can only ever issue GET and LIST. Every other method must be rejected inside request() itself,
// before any HTTP request is built or any network call attempted.
func TestRequest_RejectsWriteMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, "TRACE", "CONNECT"} {
		t.Run(method, func(t *testing.T) {
			c := &Client{addr: "http://127.0.0.1:1", token: "irrelevant", hc: &http.Client{Transport: spyTransport{t}}}
			status, body, err := c.request(context.Background(), method, "sys/health")
			if err == nil {
				t.Fatalf("request(%q) returned no error — write methods must be refused", method)
			}
			if !strings.Contains(err.Error(), "refusing HTTP method") {
				t.Fatalf("request(%q) error = %q, want it to explain the method was refused", method, err)
			}
			if status != 0 || body != nil {
				t.Fatalf("request(%q) = (%d, %v), want (0, nil) on rejection", method, status, body)
			}
		})
	}
}

// TestRequest_AllowsGetAndList proves the allowlist isn't accidentally empty — a guard that
// rejects everything, including the two methods this tool needs, would pass
// TestRequest_RejectsWriteMethods vacuously and never be caught.
func TestRequest_AllowsGetAndList(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := &Client{addr: srv.URL, token: "t", hc: srv.Client()}

	status, body, err := c.Get(context.Background(), "sys/health")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if status != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("Get = (%d, %s)", status, body)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/sys/health" {
		t.Fatalf("server saw method=%s path=%s, want GET /v1/sys/health", gotMethod, gotPath)
	}

	status, body, err = c.List(context.Background(), "sys/audit")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if status != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("List = (%d, %s)", status, body)
	}
	if gotMethod != http.MethodGet || gotQuery != "list=true" {
		t.Fatalf("server saw method=%s query=%s, want GET with list=true", gotMethod, gotQuery)
	}
}

func TestBuildTLSConfig_SkipVerifyWarnsLoudly(t *testing.T) {
	var warn bytes.Buffer
	tlsCfg, err := buildTLSConfig(Config{TLSSkipVerify: true}, &warn)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Fatal("TLSSkipVerify=true did not produce InsecureSkipVerify")
	}
	if !strings.Contains(warn.String(), "WARNING") || !strings.Contains(warn.String(), "tls-skip-verify") {
		t.Fatalf("expected a loud warning naming --tls-skip-verify, got: %q", warn.String())
	}
}

func TestBuildTLSConfig_DefaultRefusesSkipVerify(t *testing.T) {
	var warn bytes.Buffer
	tlsCfg, err := buildTLSConfig(Config{}, &warn)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tlsCfg != nil {
		t.Fatalf("expected nil tls.Config (system trust store) with no CA/skip-verify config, got %+v", tlsCfg)
	}
	if warn.Len() != 0 {
		t.Fatalf("expected no warning when --tls-skip-verify was not passed, got: %q", warn.String())
	}
}

func TestNew_RequiresAddr(t *testing.T) {
	if _, err := New(context.Background(), Config{Token: "t"}, &bytes.Buffer{}); err == nil {
		t.Fatal("New with no Addr should fail")
	}
}

func TestNew_RequiresAuth(t *testing.T) {
	if _, err := New(context.Background(), Config{Addr: "http://127.0.0.1:1"}, &bytes.Buffer{}); err == nil {
		t.Fatal("New with no token/AppRole should fail")
	}
}
