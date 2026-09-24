package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setAnomaliesCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunAnomalyList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 7's own test requirement) against
// internal/cli/anomalies/anomalies.go's runListRemote.
func TestRunAnomalyList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/anomalies" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"alerts":[{"ID":1,"SecretName":"db-pass","AlertType":"new_ip","Severity":"high","Description":"unusual IP","AccessedBy":"alice","IPAddress":"1.2.3.4","DetectedAt":"2026-01-01T00:00:00Z","Acknowledged":false}],"total":1}}`)
	}))
	defer srv.Close()
	setAnomaliesCreds(t, srv)
	anomalyUnacknowledged = false

	out := captureStdout(t, func() {
		if err := runAnomalyList(anomalyListCmd, nil); err != nil {
			t.Fatalf("runAnomalyList: %v", err)
		}
	})
	if !containsAll(out, "Anomaly Alerts (1 total)", "[1] high | new_ip", "Secret: db-pass", "User: alice", "IP: 1.2.3.4", "unusual IP") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunAnomalyAcknowledge_MatchesOldCLIOutputShape(t *testing.T) {
	var acked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			acked = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"acknowledged":true}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setAnomaliesCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runAnomalyAcknowledge(anomalyAcknowledgeCmd, []string{"5"}); err != nil {
			t.Fatalf("runAnomalyAcknowledge: %v", err)
		}
	})
	if acked != "/api/v1/audit/anomalies/5/acknowledge" {
		t.Fatalf("acked path = %q", acked)
	}
	if !containsAll(out, "Alert 5 acknowledged.") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunAnomalyConfigGet_MatchesOldCLIOutputShape matches
// internal/cli/anomalies/config.go's printAnomalyConfig.
func TestRunAnomalyConfigGet_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/anomaly-config" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"config":{"lookback_days":30,"quarantine_hours":24,"off_hours_enabled":true,"off_hours_timezone":"UTC","off_hours_start":22,"off_hours_end":6,"ml_enabled":false,"ml_threshold":0.8,"ml_num_trees":100,"ml_sample_size":256}}}`)
	}))
	defer srv.Close()
	setAnomaliesCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runAnomalyConfigGet(anomalyConfigGetCmd, nil); err != nil {
			t.Fatalf("runAnomalyConfigGet: %v", err)
		}
	})
	if !containsAll(out, "Lookback:          30 days", "Quarantine:        24 hours", "Off-hours enabled: true", "ML threshold:      0.80") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunEscalationList_MatchesOldCLIOutputShape matches
// internal/cli/anomalies/escalation.go's runEscalationListRemote.
func TestRunEscalationList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/alert-escalation-policies" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"policies":[{"id":1,"name":"critical-escalate","min_severity":"high","escalate_after_minutes":30,"channel_ids":"1,2","enabled":true}]}}`)
	}))
	defer srv.Close()
	setAnomaliesCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runEscalationList(escalationListCmd, nil); err != nil {
			t.Fatalf("runEscalationList: %v", err)
		}
	})
	if !containsAll(out, "Alert Escalation Policies (1)", "[1] critical-escalate", "min_severity=high", "after=30 min", `channels="1,2"`) {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunEscalationRun_UsesRealHumanRoute confirms the fixed route (not the old CLI's
// doomed /system proxy equivalent -- see this package's doc comment).
func TestRunEscalationRun_UsesRealHumanRoute(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			calledPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"evaluated":10,"escalated":2,"skipped":8}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setAnomaliesCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runEscalationRun(escalationRunCmd, nil); err != nil {
			t.Fatalf("runEscalationRun: %v", err)
		}
	})
	if calledPath != "/api/v1/admin/jobs/run-alert-escalation" {
		t.Fatalf("called path = %q, want the real human route, not the /system proxy", calledPath)
	}
	if !containsAll(out, "evaluated=10, escalated=2, skipped=8") {
		t.Fatalf("output = %q", out)
	}
}
