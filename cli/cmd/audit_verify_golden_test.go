package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The seal text the server puts in state_reason (internal/core/audit_seal.go
// auditSealText): seal number, time and operator.
const goldenSealText = "the audit chain is sealed: a loss of audit events was accepted with the checkpoint key " +
	"(seal #1 at 2026-11-04T15:55:43Z by ops: gap after #3, resuming at #5 (INC-12)). The rows that remain verify; " +
	"the chain is not whole and is never reported valid again (docs/operator/audit-chain-break-runbook.md)"

// verifyGolden runs `audit verify` against a server answering body and returns what it
// printed on stdout and the error (which main prints and turns into exit status 1).
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

var goldenSealedBody = `{"data":{"valid":false,"status":"sealed","chained_events":9,"unchained_events":0,"head_id":9,"head_hash":"h9","checkpointed":true,` +
	`"state_reason":` + jsonString(goldenSealText) + `}}`

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

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

// #4230: a sealed chain printed "FAILED (first broken id 0): " with an empty reason.
// It is not a break: it is a recorded, accepted loss, and the seal text is the answer.
func TestAuditVerifyGolden_Sealed(t *testing.T) {
	out, err := verifyGolden(t, goldenSealedBody, false)
	want := "Audit chain: SEALED\n" +
		"  chained events:   9\n" +
		"  unchained events: 0\n" +
		"  head id:          9\n" +
		"  head hash:        h9\n" +
		"  checkpoint:       checked against a signed in-DB checkpoint (on-box truncation detection)\n" +
		"  seal:             " + goldenSealText + "\n"
	if out != want {
		t.Fatalf("sealed output.\n got: %q\nwant: %q", out, want)
	}
	// Still non-zero (fail closed for scripts) and never worded as a break.
	wantErr := "audit chain is SEALED: " + goldenSealText
	if err == nil || err.Error() != wantErr {
		t.Fatalf("sealed error = %v, want %q", err, wantErr)
	}
	if strings.Contains(err.Error(), "FAILED") {
		t.Fatalf("a sealed chain is not reported as FAILED: %v", err)
	}
}

// A sealed chain's exit status is 1, the same as BROKEN and NOT PROVEN: 4 is "permission
// denied" in this CLI's documented exit-code contract (exitcodes.go), not the offline
// verifier's SEALED.
func TestAuditVerifyGolden_SealedExitStatusIsOne(t *testing.T) {
	_, err := verifyGolden(t, goldenSealedBody, false)
	if err == nil {
		t.Fatal("a sealed chain must exit non-zero")
	}
	code, _ := classifyError(err, true)
	if code != exitFailure {
		t.Fatalf("sealed exit status = %d, want %d", code, exitFailure)
	}
}

// --json carries the seal text in reason (what clients that render reason expect) and
// keeps state_reason as the server sent it.
func TestAuditVerifyGolden_SealedJSON(t *testing.T) {
	out, err := verifyGolden(t, goldenSealedBody, true)
	if err == nil {
		t.Fatal("a sealed chain must exit non-zero")
	}
	var got map[string]any
	if jerr := json.Unmarshal([]byte(out), &got); jerr != nil {
		t.Fatalf("--json output is not JSON: %v: %q", jerr, out)
	}
	if got["status"] != "sealed" || got["valid"] != false {
		t.Fatalf("status/valid = %v/%v", got["status"], got["valid"])
	}
	if got["reason"] != goldenSealText {
		t.Fatalf("reason = %q, want the seal text", got["reason"])
	}
	if got["state_reason"] != goldenSealText {
		t.Fatalf("state_reason = %q, want the seal text", got["state_reason"])
	}
}

// A server that (before #4241) sent no reason still gets one filled from state_reason,
// and one that sends neither still prints a sentence, never an empty reason.
func TestAuditVerifyGolden_SealedWithoutSealText(t *testing.T) {
	out, err := verifyGolden(t, `{"data":{"valid":false,"status":"sealed","head_id":9,"head_hash":"h9"}}`, false)
	if err == nil || !strings.Contains(err.Error(), "SEALED") || strings.HasSuffix(err.Error(), ": ") {
		t.Fatalf("sealed error without a seal text = %v", err)
	}
	if !strings.Contains(out, "seal:") || strings.Contains(out, "seal:             \n") {
		t.Fatalf("sealed output without a seal text has an empty seal line: %q", out)
	}
}

// BROKEN and VALID --json are unchanged.
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
