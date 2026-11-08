package http

// Regression guards for the sweep's own oracle: each one pins a way the harness
// could report a clean run without having looked. They only use the sweep's
// long-standing API, so they also compile against an unfixed harness.

import (
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/canary"
)

// A handler that logs a credential the caller also put in the URL is a leak: the
// value being in the URL says nothing about the line that carried it.
func TestCanaryOracle_HandlerLogOfURLValueIsNotWaived(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, 7)
	defer s.close()
	pw := s.byLabel["password"]
	real := s.w.router
	s.w.router = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("handler debug: authenticating with password=%s", r.URL.Query().Get("password"))
		real.ServeHTTP(w, r)
	})
	s.run(sweepReq{Method: "GET", Target: "/healthz?password=" + pw.Raw, Header: http.Header{}, Principal: "anon", Shape: "probe", Route: "GET /healthz"})
	for _, f := range s.findings() {
		if f.Surface == "log" && f.Label == "password" && !strings.Contains(f.Key, "url-echo") && !strings.Contains(f.Key, "|waived:") {
			return
		}
	}
	t.Fatalf("a handler log line carrying a URL-supplied password was not reported as a finding: %v", keysOfHits(s))
}

func keysOfHits(s *sweep) []string {
	out := make([]string, 0, len(s.hits))
	for k := range s.hits {
		out = append(out, k)
	}
	return out
}

// The at-rest scans mean nothing unless a secret-class value was really stored
// through the HTTP API: the fixture holds exactly two secrets of its own.
func TestCanarySweep_StoresSecretValuesBeforeSweeping(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, 7)
	defer s.close()
	var nodes, versions int64
	if err := s.w.db.Raw("SELECT COUNT(*) FROM secret_nodes").Scan(&nodes).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.w.db.Raw("SELECT COUNT(*) FROM secret_versions").Scan(&versions).Error; err != nil {
		t.Fatal(err)
	}
	if nodes != 4 || versions != 4 {
		t.Fatalf("secret_nodes=%d secret_versions=%d, want 4 and 4 (2 fixture + 2 stored through POST /api/v1/secrets/)", nodes, versions)
	}
}

// An identifier path param is not a credential, whatever its name contains; a
// genuine token param still is one.
func TestCanarySweep_IDParamsAreMetadata(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, 7)
	defer s.close()
	for _, param := range []string{"tokenId", "token_id", "secretID", "id"} {
		got := s.path("/x/{"+param+"}", false)
		if !strings.Contains(got, s.byLabel["m-pathparam"].Core) {
			t.Errorf("param %s filled with %q, want the metadata path canary", param, got)
		}
	}
	if got := s.path("/x/{token}", false); !strings.Contains(got, s.byLabel["token"].Core) {
		t.Errorf("param token filled with %q, want the secret token canary", got)
	}
	if c := s.fieldCanary("token_id", false); c.Class != canary.Metadata {
		t.Errorf("field token_id is class %v, want metadata", c.Class)
	}
}

// A finding file must not carry any live session credential.
func TestCanarySweep_ReproRedactsEverySessionBearer(t *testing.T) {
	for _, p := range []string{"admin", "outsider", "disposable"} {
		h := http.Header{}
		h.Set("Authorization", "Bearer live-session-value")
		repro := sweepReq{Header: h, Principal: p}.Repro()
		if got := repro["headers"].(map[string]string)["Authorization"]; strings.Contains(got, "live-session-value") {
			t.Errorf("principal %s: repro carries the bearer: %q", p, got)
		}
	}
}
