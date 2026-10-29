package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AUDIT-REQUEST-ID-2 item 1: `audit logs|search --request-id` and the id in the
// output (docs/specs/audit-request-id.md §8).

const cliReqID = "0123456789abcdef01234567"

func TestRunAuditLogs_RequestIDFlagIsSentAndWideShowsIt(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/logs" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.Query().Get("request_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"logs":[{"id":7,"event_type":"auth.login_failed","actor":"","actor_type":"user","description":"d","timestamp":"2026-10-10T01:56:04Z","request_id":%q}]}}`, cliReqID)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditLogLimit = 50
	auditLogRequestID = cliReqID
	defer func() { auditLogRequestID, auditWide = "", false }()

	plain := captureStdout(t, func() {
		if err := runAuditLogs(auditLogsCmd, nil); err != nil {
			t.Fatalf("runAuditLogs: %v", err)
		}
	})
	if gotQuery != cliReqID {
		t.Fatalf("request_id sent = %q, want %q", gotQuery, cliReqID)
	}
	if strings.Contains(plain, "REQUEST-ID") || strings.Contains(plain, cliReqID) {
		t.Fatalf("the default table must not grow a column:\n%s", plain)
	}

	auditWide = true
	wide := captureStdout(t, func() {
		if err := runAuditLogs(auditLogsCmd, nil); err != nil {
			t.Fatalf("runAuditLogs --wide: %v", err)
		}
	})
	if !containsAll(wide, "REQUEST-ID", cliReqID, "auth.login_failed") {
		t.Fatalf("--wide is missing the request id:\n%s", wide)
	}
}

func TestRunAuditSearch_RequestIDFlagIsSent(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/search" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.Query().Get("request_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"events":[]}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditSearchLimit = 100
	auditSearchRequestID = cliReqID
	defer func() { auditSearchRequestID = "" }()

	_ = captureStdout(t, func() {
		if err := runAuditSearch(auditSearchCmd, nil); err != nil {
			t.Fatalf("runAuditSearch: %v", err)
		}
	})
	if gotQuery != cliReqID {
		t.Fatalf("request_id sent = %q, want %q", gotQuery, cliReqID)
	}
}

func TestPrintAuditLogTable_WideMarksRowsWithoutAnID(t *testing.T) {
	auditWide = true
	defer func() { auditWide = false }()
	out := captureStdout(t, func() {
		printAuditLogTable([]logEntry{
			{ID: 1, EventType: "secret.read", Actor: "alice", ActorType: "user", Timestamp: "2026-10-10T01:56:04Z"},
		}, auditPageFooter{})
	})
	if !containsAll(out, "REQUEST-ID", " - ") {
		t.Fatalf("a row without a request id should show '-':\n%s", out)
	}
}
