package k8ssync

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// failClosedServer answers the three calls a Fetch makes: the environment list,
// the secret list and the value read. A nil entry is not served (404).
type failClosedServer struct {
	status map[string]int    // path prefix -> status override
	body   map[string]string // path prefix -> body
}

func (s failClosedServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := ""
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			key = "envs"
		case r.URL.Path == "/api/v1/secrets":
			key = "list"
		case strings.HasPrefix(r.URL.Path, "/api/v1/secrets/"):
			key = "value"
		}
		b, ok := s.body[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if code, ok := s.status[key]; ok {
			w.WriteHeader(code)
		}
		_, _ = w.Write([]byte(b))
	}
}

const (
	okEnvs  = `{"data":{"environments":[{"ID":3,"Name":"production"}]}}`
	okList  = `{"data":{"secrets":[{"ID":9,"Name":"db"}],"total_pages":1}}`
	okValue = `{"data":{"value":"s3cr3t","secret":{}}}`
)

func fetchWith(t *testing.T, s failClosedServer) ([]byte, error) {
	t.Helper()
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	f := NewKeyorixFetcher(srv.URL, "tok", 7)
	return f.Fetch(context.Background(), "production/db")
}

func TestFetcher_HappyPathStillWorks(t *testing.T) {
	v, err := fetchWith(t, failClosedServer{body: map[string]string{"envs": okEnvs, "list": okList, "value": okValue}})
	if err != nil || string(v) != "s3cr3t" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestFetcher_RejectsEmptyOrMissingValue(t *testing.T) {
	for name, val := range map[string]string{
		"empty":      `{"data":{"value":"","secret":{}}}`,
		"missing":    `{"data":{"secret":{}}}`,
		"null":       `{"data":{"value":null,"secret":{}}}`,
		"no payload": `{"data":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := fetchWith(t, failClosedServer{body: map[string]string{"envs": okEnvs, "list": okList, "value": val}})
			if err == nil {
				t.Fatalf("empty value accepted: %q", v)
			}
			if errors.Is(err, ErrUpstreamGone) {
				t.Fatalf("an empty value must not be classified as upstream-gone (it would prune the synced copy): %v", err)
			}
		})
	}
}

func TestFetcher_RequiresPositiveIntegerEnvironmentID(t *testing.T) {
	for name, envs := range map[string]string{
		"zero":     `{"data":{"environments":[{"ID":0,"Name":"production"}]}}`,
		"missing":  `{"data":{"environments":[{"Name":"production"}]}}`,
		"negative": `{"data":{"environments":[{"ID":-4,"Name":"production"}]}}`,
		"string":   `{"data":{"environments":[{"ID":"3","Name":"production"}]}}`,
		"float":    `{"data":{"environments":[{"ID":3.5,"Name":"production"}]}}`,
		"null":     `{"data":{"environments":[{"ID":null,"Name":"production"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			listHit := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/environments"):
					_, _ = w.Write([]byte(envs))
				case r.URL.Path == "/api/v1/secrets":
					listHit = true
					_, _ = w.Write([]byte(okList))
				default:
					_, _ = w.Write([]byte(okValue))
				}
			}))
			t.Cleanup(srv.Close)
			f := NewKeyorixFetcher(srv.URL, "tok", 7)
			if v, err := f.Fetch(context.Background(), "production/db"); err == nil {
				t.Fatalf("invalid environment id accepted, value %q", v)
			} else if errors.Is(err, ErrUpstreamGone) {
				t.Fatalf("an invalid id must not be classified as upstream-gone: %v", err)
			}
			if listHit {
				t.Fatal("the secret list was requested with an invalid environment id")
			}
		})
	}
}

func TestFetcher_RejectsNon2xx(t *testing.T) {
	for _, code := range []int{300, 301, 302, 304, 307, 308} {
		for _, stage := range []string{"envs", "list", "value"} {
			bodies := map[string]string{"envs": okEnvs, "list": okList, "value": okValue}
			v, err := fetchWith(t, failClosedServer{body: bodies, status: map[string]int{stage: code}})
			if err == nil {
				t.Errorf("status %d on %s accepted, value %q", code, stage, v)
			}
		}
	}
}

func TestSanitizeServerString(t *testing.T) {
	got := sanitizeServerString("a\r\nb\x00c\x1b[31md\x7fe\u0085f\xffg" + strings.Repeat("x", 500))
	if len(got) > maxServerErrorStringBytes {
		t.Fatalf("not truncated: %d bytes", len(got))
	}
	if !strings.HasPrefix(got, "abc[31mdefg") {
		t.Fatalf("control characters not stripped: %q", got)
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			t.Fatalf("control character %U survived", r)
		}
	}
	if s := sanitizeServerString(strings.Repeat("é", 300)); len(s) > maxServerErrorStringBytes || strings.ContainsRune(s, '�') {
		t.Fatalf("multi-byte truncation split a rune: %d bytes", len(s))
	}
}

// A server-supplied error string never reaches the returned error verbatim: a
// string that is not one of the known refusal codes is dropped, and a known code
// is printed quoted.
func TestFetcher_ServerErrorStringsAreNotEchoed(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusConflict} {
		_, err := fetchWith(t, failClosedServer{
			body:   map[string]string{"envs": `{"error":"SecretSuspended\r\nINJECTED line\u0000"}`},
			status: map[string]int{"envs": code},
		})
		if err == nil {
			t.Fatalf("status %d: expected an error", code)
		}
		if strings.ContainsAny(err.Error(), "\r\n\x00") || strings.Contains(err.Error(), "INJECTED") {
			t.Fatalf("status %d: server text leaked into the error: %q", code, err)
		}
	}
	_, err := fetchWith(t, failClosedServer{
		body:   map[string]string{"envs": `{"error":"SecretSuspended"}`},
		status: map[string]int{"envs": http.StatusConflict},
	})
	if !errors.Is(err, ErrSourceSuspended) || !strings.Contains(err.Error(), `"SecretSuspended"`) {
		t.Fatalf("known refusal code should stay classified and be quoted: %v", err)
	}
}
