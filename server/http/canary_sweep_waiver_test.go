package http

import (
	"fmt"
	"log"
	"net/url"
	"regexp"
	"testing"
)

// Every waiver names its reason, and an open defect names its issue.
func TestCanarySweepWaivers_WellFormed(t *testing.T) {
	issue := regexp.MustCompile(`^#\d+$`)
	seen := map[string]bool{}
	for _, w := range sweepWaivers {
		if w.ID == "" || seen[w.ID] {
			t.Errorf("waiver id %q is empty or duplicated", w.ID)
		}
		seen[w.ID] = true
		if w.Route == "" || w.Label == "" || w.Surface == "" || w.Why == "" {
			t.Errorf("waiver %s must set route, label, surface and why: %+v", w.ID, w)
		}
		if w.Kind != sweepWaiverOpenDefect && w.Kind != sweepWaiverContract {
			t.Errorf("waiver %s has unknown kind %q", w.ID, w.Kind)
		}
		if !issue.MatchString(w.Ref) {
			t.Errorf("waiver %s must name an issue, got %q", w.ID, w.Ref)
		}
	}
}

// The log waiver covers only the URI of the request's own access log record.
func TestCanarySweepWaiver_OnlyTheAccessRecordURI(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, 7)
	defer s.close()

	// No production row waives a log hit any more (the setup-encoded-slash row
	// was removed with #4045's fix), so install the row this test exercises for
	// its duration only.
	origWaivers := sweepWaivers
	defer func() { sweepWaivers = origWaivers }()
	sweepWaivers = append(append([]sweepWaiver(nil), origWaivers...), sweepWaiver{
		ID: "test-log-row", Route: "GET /auth/setup/{token}", Label: "token-h", Surface: "log",
		Kind: sweepWaiverOpenDefect, Ref: "#4045", Why: "test-only row: exercises the access-record URI matching.",
	})

	const route, addr, status = "GET /auth/setup/{token}", "198.18.0.9:4242", 404
	c := s.byLabel["token-h"]
	req := sweepReq{Method: "GET", Route: route, Target: "/auth/setup/" + url.PathEscape(c.Raw), Principal: "anon", RemoteAddr: addr}
	access := func(uri, peer string, code int) string {
		return fmt.Sprintf(`2026/11/08 11:02:28 "GET http://example.com%s HTTP/1.1" from %s - %d 9B in 12µs`, uri, peer, code)
	}
	echoed := "/auth/setup/[REDACTED]/" + c.Raw

	cases := []struct {
		name, route, label, line string
		status                   int
		wantWaived               bool
	}{
		{"access record of this request", route, "token-h", access(echoed, addr, status), status, true},
		{"other log line", route, "token-h", "handler debug: token=" + c.Raw, status, false},
		{"access record, other status", route, "token-h", access(echoed, addr, 200), status, false},
		{"access record, other peer", route, "token-h", access(echoed, "198.18.0.10:4242", status), status, false},
		{"canary after the record", route, "token-h", access("/auth/setup/[REDACTED]", addr, status) + " " + c.Raw, status, false},
		{"other route", "GET /other", "token-h", access(echoed, addr, status), status, false},
		{"other label", route, "token", access("/auth/setup/[REDACTED]/"+s.byLabel["token"].Raw, addr, status), status, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.hits = map[string]*sweepHitRec{}
			s.usedWaivers = map[string]bool{}
			r := req
			r.Route = tc.route
			if tc.label != "token-h" {
				r.Target = "/auth/setup/" + url.PathEscape(s.byLabel[tc.label].Raw)
			}
			s.scanLog(tc.route, &r, []byte(tc.line+"\n"), tc.status)
			if len(s.hits) == 0 {
				t.Fatal("scanner found nothing: the case does not exercise the waiver")
			}
			for k, h := range s.hits {
				if waived := h.Waiver != ""; waived != tc.wantWaived {
					t.Errorf("hit %s: waived=%v, want %v", k, waived, tc.wantWaived)
				}
			}
		})
	}
}

// A row nothing matched is reported, so a fixed defect cannot keep its waiver.
func TestCanarySweepWaiver_UnusedRowIsReported(t *testing.T) {
	s := &sweep{usedWaivers: map[string]bool{}}
	for _, w := range sweepWaivers[1:] {
		s.usedWaivers[w.ID] = true
	}
	stale := s.staleWaivers()
	if len(stale) != 1 || stale[0] != sweepWaivers[0].ID {
		t.Fatalf("stale = %v, want only %s", stale, sweepWaivers[0].ID)
	}
	s.usedWaivers[sweepWaivers[0].ID] = true
	if stale := s.staleWaivers(); len(stale) != 0 {
		t.Fatalf("stale = %v, want none", stale)
	}
}

// Destructive routes must not touch the long-lived sessions, or the rest of the
// sweep silently runs unauthenticated.
func TestCanarySweep_DestructiveRoutesSpareLongLivedSessions(t *testing.T) {
	origLog := log.Writer()
	defer log.SetOutput(origLog)
	s := newSweep(t, 7)
	defer s.close()
	for _, rt := range listSweepRoutes(t, s.w.router) {
		if sweepDestructive.MatchString(rt.Pattern) && rt.Method != "CONNECT" && rt.Method != "TRACE" {
			s.driveRoute(rt)
		}
	}
	if len(s.scanFailures) > 0 {
		t.Fatalf("scan failures: %v", s.scanFailures)
	}
	if !s.sessionLive(s.w.adminTok) {
		t.Error("admin session died on a destructive route")
	}
	if !s.sessionLive(s.outsiderTok) {
		t.Error("outsider session died on a destructive route")
	}
}
