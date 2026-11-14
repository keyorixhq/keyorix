package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// While the audit log refuses writes an activation still succeeds, DEGRADED: the API
// reports activation.degraded (and audit_settled_at once the owed rows are written).
// The CLI used to print the same text for it as for a normal one.

func bgFakeServer(t *testing.T, status int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/1/break-glass" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	setBGCreds(t, srv)
}

func runBGActivateOut(t *testing.T, body string) string {
	t.Helper()
	bgFakeServer(t, http.StatusCreated, body)
	bgProject, bgJustify = 1, "incident INC-1"
	defer func() { bgProject, bgJustify = 0, "" }()
	return captureStdout(t, func() {
		if err := runBGActivate(bgActivateCmd, nil); err != nil {
			t.Fatalf("runBGActivate: %v", err)
		}
	})
}

func runBGListOut(t *testing.T, body string) string {
	t.Helper()
	bgFakeServer(t, http.StatusOK, body)
	bgProject = 1
	defer func() { bgProject = 0 }()
	return captureStdout(t, func() {
		if err := runBGList(bgListCmd, nil); err != nil {
			t.Fatalf("runBGList: %v", err)
		}
	})
}

const (
	bgActivationNormal   = `{"id":42,"user_id":7,"username":"alice","role_name":"proj-dev","justification":"incident INC-1","state":"active","expires_at":"2026-01-02T00:00:00Z","created_at":"2026-01-01T20:00:00Z"}`
	bgActivationDegraded = `{"id":43,"user_id":8,"username":"bob","role_name":"proj-dev","justification":"audit down","state":"active","expires_at":"2026-01-01T20:15:00Z","created_at":"2026-01-01T20:00:00Z","degraded":true}`
	bgActivationSettled  = `{"id":44,"user_id":9,"username":"carol","role_name":"proj-dev","justification":"earlier outage","state":"expired","expires_at":"2026-01-01T10:15:00Z","created_at":"2026-01-01T10:00:00Z","degraded":true,"audit_settled_at":"2026-01-01T10:40:00Z"}`
)

func TestRunBGActivate_DegradedSaysSoInOneLine(t *testing.T) {
	out := runBGActivateOut(t, `{"success":true,"data":{"activation":`+strings.Replace(bgActivationDegraded, `"id":43`, `"id":42`, 1)+`}}`)

	var note []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "DEGRADED") {
			note = append(note, l)
		}
	}
	if len(note) != 1 {
		t.Fatalf("want exactly one DEGRADED line, got %d in %q", len(note), out)
	}
	if !containsAll(note[0], "audit log", "owed", "review is mandatory") {
		t.Fatalf("the note does not say why it is degraded and what is owed: %q", note[0])
	}
	// The first line is the old CLI's, unchanged.
	if !strings.HasPrefix(out, "Emergency access activated (id=42): role \"proj-dev\" until 2026-01-01T20:15:00Z.\n") {
		t.Fatalf("first line changed: %q", out)
	}
}

func TestRunBGActivate_NormalActivationHasNoDegradedNote(t *testing.T) {
	out := runBGActivateOut(t, `{"success":true,"data":{"activation":`+bgActivationNormal+`}}`)
	if strings.Contains(out, "DEGRADED") || strings.Contains(strings.ToLower(out), "owed") {
		t.Fatalf("a normal activation mentions the degraded path: %q", out)
	}
}

func TestRunBGList_MarksDegradedRows(t *testing.T) {
	out := runBGListOut(t, `{"success":true,"data":{"activations":[`+bgActivationNormal+`,`+bgActivationDegraded+`,`+bgActivationSettled+`],"count":3}}`)

	rows := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		for _, who := range []string{"alice", "bob", "carol"} {
			if strings.Contains(l, who) {
				rows[who] = l
			}
		}
	}
	if len(rows) != 3 {
		t.Fatalf("missing rows: %q", out)
	}
	if strings.Contains(rows["alice"], "DEGRADED") {
		t.Fatalf("the normal row is marked DEGRADED: %q", rows["alice"])
	}
	if !strings.Contains(rows["bob"], "DEGRADED") || strings.Contains(rows["bob"], "settled") {
		t.Fatalf("the degraded row with audit still owed: %q", rows["bob"])
	}
	if !containsAll(rows["carol"], "DEGRADED", "settled") {
		t.Fatalf("the degraded row whose audit rows were written: %q", rows["carol"])
	}
	// A legend line explains the marker, once.
	if strings.Count(out, "DEGRADED = ") != 1 {
		t.Fatalf("want one legend line for DEGRADED: %q", out)
	}
	// The justification stays the last column, free text after the marker.
	if !strings.HasSuffix(strings.TrimSpace(rows["bob"]), "audit down") {
		t.Fatalf("justification is no longer the last column: %q", rows["bob"])
	}
}

// With no degraded activation the list is byte-for-byte what it was: no AUDIT column,
// no legend.
func TestRunBGList_NoDegradedRowsLeavesTheListUnchanged(t *testing.T) {
	out := runBGListOut(t, `{"success":true,"data":{"activations":[`+bgActivationNormal+`],"count":1}}`)
	want := "Break-glass activations — project 1:\n\n" +
		"ID    USER  STATE     ROLE     EXPIRES (UTC)        JUSTIFICATION\n" +
		"42    alice active    proj-dev 2026-01-02 00:00:00  incident INC-1\n"
	if out != want {
		t.Fatalf("list output changed.\n got: %q\nwant: %q", out, want)
	}
}
