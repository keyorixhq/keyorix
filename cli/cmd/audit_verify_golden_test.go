package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// verifyGolden runs `audit verify` against a server answering body and returns what it
// printed on stdout and the error (which main prints and turns into a non-zero exit status).
func verifyGolden(t *testing.T, body string, asJSON bool) (string, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON, auditVerifyFull = asJSON, false
	defer func() { auditVerifyJSON = false }()

	var err error
	out := captureStdout(t, func() { err = runAuditVerify(auditVerifyCmd, nil) })
	return out, err
}

const (
	goldenValidBody  = `{"data":{"valid":true,"status":"valid","chained_events":42,"unchained_events":0,"head_id":42,"head_hash":"abc123","checkpointed":true}}`
	goldenBrokenBody = `{"data":{"valid":false,"status":"broken","chained_events":9,"unchained_events":0,"head_id":9,"head_hash":"h9","checkpointed":true,` +
		`"first_broken_id":7,"reason":"event #7's recorded entry_hash does not match the row's contents"}}`
)

func TestAuditVerifyGolden_Valid(t *testing.T) {
	out, err := verifyGolden(t, goldenValidBody, false)
	if err != nil {
		t.Fatalf("valid chain must exit 0: %v", err)
	}
	want := "Audit chain: VALID\n" +
		"  chained events:   42\n" +
		"  unchained events: 0\n" +
		"  head id:          42\n" +
		"  head hash:        abc123\n" +
		"  checkpoint:       checked against a signed in-DB checkpoint (on-box truncation detection)\n"
	if out != want {
		t.Fatalf("valid output changed.\n got: %q\nwant: %q", out, want)
	}
}

func TestAuditVerifyGolden_Broken(t *testing.T) {
	out, err := verifyGolden(t, goldenBrokenBody, false)
	want := "Audit chain: BROKEN\n" +
		"  chained events:   9\n" +
		"  unchained events: 0\n" +
		"  head id:          9\n" +
		"  head hash:        h9\n" +
		"  checkpoint:       checked against a signed in-DB checkpoint (on-box truncation detection)\n" +
		"  first broken id:  7\n" +
		"  reason:           event #7's recorded entry_hash does not match the row's contents\n"
	if out != want {
		t.Fatalf("broken output changed.\n got: %q\nwant: %q", out, want)
	}
	wantErr := "audit chain verification FAILED (first broken id 7): event #7's recorded entry_hash does not match the row's contents"
	if err == nil || err.Error() != wantErr {
		t.Fatalf("broken error = %v, want %q", err, wantErr)
	}
}

// BROKEN and VALID --json carry no state_reason.
func TestAuditVerifyGolden_JSONOfValidAndBrokenUnchanged(t *testing.T) {
	out, _ := verifyGolden(t, goldenBrokenBody, true)
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %q", out)
	}
	if got["reason"] != "event #7's recorded entry_hash does not match the row's contents" || got["first_broken_id"] != float64(7) {
		t.Fatalf("broken --json changed: %v", got)
	}
	if _, has := got["state_reason"]; has {
		t.Fatalf("a broken --json grew a state_reason: %v", got)
	}
	out, err := verifyGolden(t, goldenValidBody, true)
	if err != nil {
		t.Fatalf("valid --json must exit 0: %v", err)
	}
	if !strings.Contains(out, `"valid":true`) || strings.Contains(out, "state_reason") {
		t.Fatalf("valid --json changed: %q", out)
	}
}
