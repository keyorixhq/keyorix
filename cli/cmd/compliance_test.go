package cmd

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func setComplianceCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunComplianceReport_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 8's own test requirement) against
// internal/cli/compliance/compliance.go's reportCmd.
func TestRunComplianceReport_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/posture" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"generated_at":"2026-01-01T00:00:00Z","audit_integrity":{"chain_verified":true,"chained_events":10,"checkpointed":true},"legal_hold":{"active":false},"retention":{"enabled":false}}}`)
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)

	out := captureStdout(t, func() {
		if err := complianceReportCmd.RunE(complianceReportCmd, nil); err != nil {
			t.Fatalf("compliance report: %v", err)
		}
	})
	if !containsAll(out, "Compliance posture — 2026-01-01T00:00:00Z", "chain verified : yes (10 chained events)", "none — purges run normally", "not configured — compliance records kept indefinitely") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestComplianceExportVerify_RoundTrip covers export --output then verify against the
// written file + detached .sig, matching internal/cli/compliance/compliance.go's
// exportCmd/verifyCmd contract exactly (canonical filename travels with the signature).
func TestComplianceExportVerify_RoundTrip(t *testing.T) {
	dataB64 := base64.StdEncoding.EncodeToString([]byte(`{"posture":{}}` + "\n"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/compliance/evidence" && r.Method == http.MethodGet:
			_, _ = fmt.Fprintf(w, `{"data":{"filename":"evidence-2026-01-01.json","data_b64":"%s","signature":"sig123","signed":true}}`, dataB64)
		case r.URL.Path == "/api/v1/compliance/evidence/verify" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":{"valid":true,"key_version":"v1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)

	dir := t.TempDir()
	out := filepath.Join(dir, "evidence.json")
	complianceExportOutput = out
	complianceExportForce = false

	captureStdout(t, func() {
		if err := complianceExportCmd.RunE(complianceExportCmd, nil); err != nil {
			t.Fatalf("compliance export: %v", err)
		}
	})

	complianceVerifyFile = out
	complianceVerifySig = ""
	verifyOut := captureStdout(t, func() {
		if err := complianceVerifyCmd.RunE(complianceVerifyCmd, nil); err != nil {
			t.Fatalf("compliance verify: %v", err)
		}
	})
	if !containsAll(verifyOut, "VALID —", "key version v1") {
		t.Fatalf("verify output = %q", verifyOut)
	}
}

func TestRunComplianceControls_CSV_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/controls.csv" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = fmt.Fprint(w, "name,area,status\nmfa,identity,pass\n")
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	complianceControlsCSV = true
	complianceControlsOutput = ""
	complianceControlsForce = false
	defer func() { complianceControlsCSV = false }()

	out := captureStdout(t, func() {
		if err := complianceControlsCmd.RunE(complianceControlsCmd, nil); err != nil {
			t.Fatalf("compliance controls --csv: %v", err)
		}
	})
	if !strings.Contains(out, "name,area,status") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunComplianceDigest_Send_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/digest/send" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"sent":true}}`)
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	complianceDigestSend = true
	defer func() { complianceDigestSend = false }()

	out := captureStdout(t, func() {
		if err := complianceDigestCmd.RunE(complianceDigestCmd, nil); err != nil {
			t.Fatalf("compliance digest --send: %v", err)
		}
	})
	if !containsAll(out, "Compliance digest broadcast to notification channels.") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunCompliancePermissionChanges_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/permission-changes" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"since":"2026-01-01T00:00:00Z","until":"2026-01-31T00:00:00Z","total":1,"changes":[{"event_id":1,"action":"grant","actor_name":"alice","target_user":"bob","role_name":"admin","scope":"global","changed_at":"2026-01-15T00:00:00Z"}]}}`)
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	compliancePermChangeSince, compliancePermChangeUntil, compliancePermChangeLimit = "", "", 0

	out := captureStdout(t, func() {
		if err := compliancePermissionChangesCmd.RunE(compliancePermissionChangesCmd, nil); err != nil {
			t.Fatalf("compliance permission-changes: %v", err)
		}
	})
	if !containsAll(out, "Permission change audit trail (1 events", "alice", "grant", "bob", "admin", "global") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunCompliancePermissionBaseline_CSV_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/permission-baseline.csv" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = fmt.Fprint(w, "user,role,permission\nalice,admin,roles.assign\n")
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	compliancePermBaselineFormat, compliancePermBaselineOutput, compliancePermBaselineForce = "csv", "", false

	out := captureStdout(t, func() {
		if err := compliancePermissionBaselineCmd.RunE(compliancePermissionBaselineCmd, nil); err != nil {
			t.Fatalf("compliance permission-baseline: %v", err)
		}
	})
	if !strings.Contains(out, "user,role,permission") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunComplianceInventory_DeploymentWide_UsesCorrectRoute(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath = r.URL.Path
		w.Header().Set("Content-Type", "text/csv")
		_, _ = fmt.Fprint(w, "name,project\n")
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	complianceInventoryProject, complianceInventoryOutput, complianceInventoryForce = 0, "", false

	captureStdout(t, func() {
		if err := complianceInventoryCmd.RunE(complianceInventoryCmd, nil); err != nil {
			t.Fatalf("compliance inventory: %v", err)
		}
	})
	if calledPath != "/api/v1/secrets/inventory.csv" {
		t.Fatalf("called path = %q", calledPath)
	}
}

func TestRunComplianceInventory_ProjectScoped_UsesCorrectRoute(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath = r.URL.Path
		w.Header().Set("Content-Type", "text/csv")
		_, _ = fmt.Fprint(w, "name,project\n")
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	complianceInventoryProject, complianceInventoryOutput, complianceInventoryForce = 12, "", false
	defer func() { complianceInventoryProject = 0 }()

	captureStdout(t, func() {
		if err := complianceInventoryCmd.RunE(complianceInventoryCmd, nil); err != nil {
			t.Fatalf("compliance inventory --project: %v", err)
		}
	})
	if calledPath != "/api/v1/projects/12/secrets/inventory.csv" {
		t.Fatalf("called path = %q", calledPath)
	}
}

func TestRunComplianceCredentialTrends_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/compliance/credential-trends") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"days":30,"points":[{"date":"2026-01-01T00:00:00Z","stale_pats":1,"expired_pats":2,"stale_machines":3,"total_pats":10,"total_machines":5}]}}`)
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	complianceCredTrendDays = 30

	out := captureStdout(t, func() {
		if err := complianceCredentialTrendsCmd.RunE(complianceCredentialTrendsCmd, nil); err != nil {
			t.Fatalf("compliance credential-trends: %v", err)
		}
	})
	if !containsAll(out, "Credential hygiene trends — last 30 days", "2026-01-01") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunComplianceRotationByBackend_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/rotation-by-backend" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"generated_at":"2026-01-01T00:00:00Z","total_overdue":3,"backends":[{"backend":"vault","total":10,"overdue":3,"up_to_date":7,"never_rotated":0}]}}`)
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)

	out := captureStdout(t, func() {
		if err := complianceRotationByBackendCmd.RunE(complianceRotationByBackendCmd, nil); err != nil {
			t.Fatalf("compliance rotation-by-backend: %v", err)
		}
	})
	if !containsAll(out, "Total overdue: 3", "vault") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}
