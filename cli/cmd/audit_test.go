package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setAuditCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunAuditVerify_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 7's own test requirement) against
// internal/cli/audit/audit.go's verifyCmd.
func TestRunAuditVerify_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/verify" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"valid":true,"chained_events":42,"unchained_events":0,"head_id":42,"head_hash":"abc123","checkpointed":true}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON = false

	out := captureStdout(t, func() {
		if err := runAuditVerify(auditVerifyCmd, nil); err != nil {
			t.Fatalf("runAuditVerify: %v", err)
		}
	})
	if !containsAll(out, "Audit chain: VALID", "chained events:   42", "head id:          42", "head hash:        abc123",
		"checked against a signed in-DB checkpoint") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunAuditVerify_BrokenChainReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"valid":false,"first_broken_id":7,"reason":"hash mismatch"}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON = false

	err := runAuditVerify(auditVerifyCmd, nil)
	if err == nil || !containsAll(err.Error(), "FAILED", "hash mismatch") {
		t.Fatalf("err = %v, want a broken-chain error", err)
	}
}

// TestRunAuditLogs_MatchesOldCLIOutputShape matches internal/cli/audit/audit.go's
// printAuditLogTable.
func TestRunAuditLogs_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/logs" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"logs":[{"id":1,"event_type":"secret.read","actor":"alice","actor_type":"user","description":"read db-pass","timestamp":"2026-01-01T00:00:00Z"}],"total":1}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditLogLimit = 50
	auditLogEventType, auditLogUserID, auditLogProjectID, auditLogActorType, auditLogSince, auditLogUntil = "", 0, 0, "", "", ""

	out := captureStdout(t, func() {
		if err := runAuditLogs(auditLogsCmd, nil); err != nil {
			t.Fatalf("runAuditLogs: %v", err)
		}
	})
	if !containsAll(out, "ID", "TIME", "ACTOR", "secret.read", "alice", "read db-pass", "Showing 1 of 1 total event(s).") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunAuditCheckpoint_MatchesOldCLIOutputShape matches audit.go's checkpointCmd.
func TestRunAuditCheckpoint_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/checkpoint" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":1,"chained_events":42,"head_id":42,"head_hash":"abc123"}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runAuditCheckpoint(auditCheckpointCmd, nil); err != nil {
			t.Fatalf("runAuditCheckpoint: %v", err)
		}
	})
	if !containsAll(out, "Audit checkpoint written:", "id:             1", "chained events: 42") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunAuditMigrateChain_DryRunDefault matches audit.go's migrateChainCmd default
// (preview-only) behavior.
func TestRunAuditMigrateChain_DryRunDefault(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/migrate-chain-encoding" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"dry_run":true,"rows_migrated":10,"unchained_rows_skipped":2,"head_id":42,"head_hash":"abc123"}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditMigrateConfirm = false

	out := captureStdout(t, func() {
		if err := runAuditMigrateChain(auditMigrateChainCmd, nil); err != nil {
			t.Fatalf("runAuditMigrateChain: %v", err)
		}
	})
	if !containsAll(out, "DRY RUN — nothing was written.", "rows migrated:          10") {
		t.Fatalf("output = %q", out)
	}
	if !containsAll(gotQuery, "dry_run=true") {
		t.Fatalf("query = %q, want dry_run=true", gotQuery)
	}
}
