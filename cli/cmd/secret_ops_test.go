// secret_ops_test.go — flag-validation and golden-output tests for PR 5's remaining
// commands (rotation-simulate, auto-rotate, bulk-rotate/rename/delete, expiring,
// orphaned, name-conformance, quota-report, ownership-history, reassign-owner,
// score, blast-radius, cert, audit, render, export, explain).
package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
)

// ── required-flag validation ─────────────────────────────────────────────────

func TestRunSecretRotationSimulate_RequiresID(t *testing.T) {
	rotationSimulateID = 0
	if err := runSecretRotationSimulate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretAutoRotate_RequiresID(t *testing.T) {
	autoRotateID = 0
	if err := runSecretAutoRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretAutoRotate_RejectsUnknownCharset(t *testing.T) {
	autoRotateID = 1
	autoRotateCharset = "not-a-real-charset"
	defer func() { autoRotateID, autoRotateCharset = 0, "" }()
	if err := runSecretAutoRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error for an unknown --charset value")
	}
}

func TestRunSecretAutoRotate_RequiresBackendAndRefTogether(t *testing.T) {
	autoRotateID = 1
	autoRotateBackend = "vault"
	autoRotateRef = ""
	defer func() { autoRotateID, autoRotateBackend = 0, "" }()
	if err := runSecretAutoRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --backend is set without --ref")
	}
}

func TestRunSecretBulkRotate_RequiresProject(t *testing.T) {
	bulkRotateProject = 0
	bulkRotateConfirm = true
	defer func() { bulkRotateConfirm = false }()
	if err := runSecretBulkRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretBulkRotate_RequiresConfirm(t *testing.T) {
	bulkRotateProject = 1
	bulkRotateConfirm = false
	defer func() { bulkRotateProject = 0 }()
	if err := runSecretBulkRotate(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --confirm is omitted")
	}
}

func TestRunSecretBulkRename_RequiresProject(t *testing.T) {
	bulkRenameProject = 0
	bulkRenamePairs = []string{"1=NEW_NAME"}
	defer func() { bulkRenamePairs = nil }()
	if err := runSecretBulkRename(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretBulkRename_RequiresAtLeastOneRename(t *testing.T) {
	bulkRenameProject = 1
	bulkRenamePairs = nil
	defer func() { bulkRenameProject = 0 }()
	if err := runSecretBulkRename(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when no --rename is given")
	}
}

func TestParseSecretRenamePairs_RejectsMalformedPair(t *testing.T) {
	if _, err := parseSecretRenamePairs([]string{"not-a-valid-pair"}); err == nil {
		t.Fatal("expected an error for a pair missing '='")
	}
	if _, err := parseSecretRenamePairs([]string{"abc=NEW_NAME"}); err == nil {
		t.Fatal("expected an error for a non-numeric ID")
	}
	if _, err := parseSecretRenamePairs([]string{"1="}); err == nil {
		t.Fatal("expected an error for an empty new name")
	}
}

func TestRunSecretBulkDelete_RequiresIDsOrNames(t *testing.T) {
	bulkDeleteIDs, bulkDeleteNames = nil, nil
	if err := runSecretBulkDelete(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when neither --ids nor --names is given")
	}
}

func TestRunSecretBulkDelete_NamesRequireProjectAndEnv(t *testing.T) {
	bulkDeleteIDs = nil
	bulkDeleteNames = []string{"s1"}
	bulkDeleteProject, bulkDeleteEnv = 0, 0
	defer func() { bulkDeleteNames = nil }()
	if err := runSecretBulkDelete(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --names is used without --project/--env")
	}
}

func TestRunSecretExpiring_RequiresProject(t *testing.T) {
	expiringProject = 0
	if err := runSecretExpiring(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretOrphaned_RequiresProject(t *testing.T) {
	orphanedProject = 0
	if err := runSecretOrphaned(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretOwnershipHistory_RequiresID(t *testing.T) {
	ownershipHistoryID = 0
	if err := runSecretOwnershipHistory(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretReassignOwner_RequiresAllFlags(t *testing.T) {
	reassignProject, reassignFrom, reassignTo = 0, 0, 0
	if err := runSecretReassignOwner(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project/--from/--to are omitted")
	}
}

func TestRunSecretScore_RequiresID(t *testing.T) {
	scoreID = 0
	if err := runSecretScore(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretAudit_RequiresID(t *testing.T) {
	auditID = 0
	if err := runSecretAudit(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

func TestRunSecretBlastRadius_RejectsNonNumericArg(t *testing.T) {
	if err := runSecretBlastRadius(&cobra.Command{}, []string{"not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric secret ID argument")
	}
}

func TestRunSecretCert_RejectsNonNumericArg(t *testing.T) {
	if err := runSecretCert(&cobra.Command{}, []string{"not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric secret ID argument")
	}
}

func TestRunSecretRender_RequiresProject(t *testing.T) {
	renderProject = 0
	if err := runSecretRender(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project is omitted")
	}
}

func TestRunSecretExport_RequiresProjectAndEnv(t *testing.T) {
	exportProject, exportEnv = 0, 0
	if err := runSecretExport(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --project/--env are omitted")
	}
}

func TestRunSecretImport_RequiresFile(t *testing.T) {
	importFile = ""
	if err := runSecretImport(&cobra.Command{}, nil); err == nil {
		t.Fatal("expected an error when --file is omitted")
	}
}

func TestRunSecretScan_RejectsInvalidSeverity(t *testing.T) {
	scanSeverity = "not-a-real-severity"
	defer func() { scanSeverity = "" }()
	if err := runSecretScan(&cobra.Command{}, []string{t.TempDir()}); err == nil {
		t.Fatal("expected an error for an invalid --severity value")
	}
}

// ── golden-output / decode-correctness tests ─────────────────────────────────

func TestRunSecretExpiring_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"expiring":[{"id":7,"name":"db-pass","type":"generic","environment_id":3,"expiration":"2026-12-01T00:00:00Z","expired":false}],"total":1,"truncated":false}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	expiringProject = 1
	defer func() { expiringProject = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretExpiring(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretExpiring: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "TYPE", "STATE", "EXPIRES", "7", "db-pass", "generic", "expiring") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretQuotaReport_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secrets":[{"secret_id":3,"secret_name":"api-key","read_count":9,"max_reads":10,"usage_pct":90,"status":"warning"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretQuotaReport(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretQuotaReport: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "READ_COUNT", "MAX_READS", "USAGE%", "STATUS", "3", "api-key", "9", "10", "90%", "warning") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretScore_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secret_id":5,"secret_name":"db-pass","score":42,"band":"medium","factors":[{"key":"rotation","label":"Rotation age","score":10,"weight":0.3,"detail":"90 days"}],"degraded":false}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	scoreID = 5
	defer func() { scoreID = 0 }()

	out := captureStdout(t, func() {
		if err := runSecretScore(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretScore: %v", err)
		}
	})
	if !containsAll(out, "db-pass", "42/100", "MEDIUM", "rotation", "90 days") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretBlastRadius_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"source_secret_id":1,"source_secret_name":"root-cert","dependents":[{"secret_id":2,"secret_name":"leaf-cert","project_id":1,"owner_id":1,"depth":1,"risk_level":"high"}],"total_impact":1,"max_depth":1,"truncated":false}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretBlastRadius(&cobra.Command{}, []string{"1"}); err != nil {
			t.Fatalf("runSecretBlastRadius: %v", err)
		}
	})
	if !containsAll(out, "root-cert", "leaf-cert", "depth 1", "high") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretCert_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secret_id":1,"secret_name":"tls-cert","subject":"CN=example.com","issuer":"CN=example.com","serial_number":"01","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","days_until_expiry":90,"is_expired":false,"is_ca":false,"self_signed":true,"signature_algorithm":"SHA256-RSA","public_key_algorithm":"RSA"}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSecretCert(&cobra.Command{}, []string{"1"}); err != nil {
			t.Fatalf("runSecretCert: %v", err)
		}
	})
	if !containsAll(out, "tls-cert", "CN=example.com", "self-signed", "90 days left") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretNameConformance_OrgWide_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"policy_enabled":true,"total_secrets":2,"violations":[{"project_id":1,"project_name":"web","id":9,"name":"bad name","type":"generic","reason":"contains space"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	nameConformanceProject = 0

	out := captureStdout(t, func() {
		if err := runSecretNameConformance(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretNameConformance: %v", err)
		}
	})
	if !containsAll(out, "PROJECT", "web", "bad name", "contains space") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretReassignOwner_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"reassigned":3}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	reassignProject, reassignFrom, reassignTo = 1, 2, 3
	defer func() { reassignProject, reassignFrom, reassignTo = 0, 0, 0 }()

	out := captureStdout(t, func() {
		if err := runSecretReassignOwner(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretReassignOwner: %v", err)
		}
	})
	if !containsAll(out, "Reassigned 3 secret(s)", "user 2", "user 3") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretBulkRotate_MatchesExpectedOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"triggered":[1,2],"failed":[{"secret_id":3,"name":"skip-me","error":"no auto-rotate configured"}],"total":3}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	bulkRotateProject, bulkRotateConfirm = 1, true
	defer func() { bulkRotateProject, bulkRotateConfirm = 0, false }()

	out := captureStdout(t, func() {
		if err := runSecretBulkRotate(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretBulkRotate: %v", err)
		}
	})
	if !containsAll(out, "2 scheduled", "1 failed", "skip-me", "no auto-rotate configured") {
		t.Fatalf("output missing expected fields, got: %q", out)
	}
}

func TestRunSecretBulkDelete_PreviewWithoutConfirm(t *testing.T) {
	bulkDeleteIDs = []int{1, 2, 3}
	bulkDeleteNames = nil
	bulkDeleteConfirm = false
	defer func() { bulkDeleteIDs, bulkDeleteConfirm = nil, false }()

	out := captureStdout(t, func() {
		if err := runSecretBulkDelete(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runSecretBulkDelete: %v", err)
		}
	})
	if !containsAll(out, "Would delete 3 secret(s)", "1, 2, 3", "Pass --confirm") {
		t.Fatalf("output missing expected preview text, got: %q", out)
	}
}
