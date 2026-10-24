package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accessreport"
	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// fakeAccessVault serves the Vault reads plan/apply/audit-access make: two KV mounts, one
// default-convention policy (secret/data/team-a/prod/* read) attached to one AppRole role, and
// a kv1/ mount that holds team-a/prod/ only when kv1HoldsTeamAProd is set. forbidden paths
// answer 403; anything not listed answers 404 (Vault's "nothing there").
type fakeAccessVault struct {
	mu                sync.Mutex
	kv1HoldsTeamAProd bool
	forbidden         map[string]bool
	extra             map[string]string
}

func (f *fakeAccessVault) setKV1HoldsTeamAProd(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kv1HoldsTeamAProd = v
}

func (f *fakeAccessVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := r.URL.Path
	if r.URL.Query().Get("list") == "true" {
		key = "LIST " + key
	}
	if f.forbidden[key] {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	bodies := map[string]string{
		"/v1/sys/mounts":                      `{"data":{"secret/":{"type":"kv","options":{"version":"2"}},"kv1/":{"type":"kv"}}}`,
		"LIST /v1/sys/policies/acl":           `{"data":{"keys":["team-a-prod-ro"]}}`,
		"/v1/sys/policies/acl/team-a-prod-ro": `{"data":{"name":"team-a-prod-ro","policy":"path \"secret/data/team-a/prod/*\" { capabilities = [\"read\"] }"}}`,
		"/v1/sys/auth":                        `{"data":{"approle/":{"type":"approle"}}}`,
		"LIST /v1/auth/approle/role":          `{"data":{"keys":["ci"]}}`,
		"/v1/auth/approle/role/ci":            `{"data":{"token_policies":["team-a-prod-ro"]}}`,
		"LIST /v1/secret/metadata":            `{"data":{"keys":["team-a/"]}}`,
		"LIST /v1/secret/metadata/team-a":     `{"data":{"keys":["prod/"]}}`,
	}
	if f.kv1HoldsTeamAProd {
		bodies["LIST /v1/kv1"] = `{"data":{"keys":["team-a/"]}}`
		bodies["LIST /v1/kv1/team-a"] = `{"data":{"keys":["prod/"]}}`
	}
	for k, v := range f.extra {
		bodies[k] = v
	}
	body, ok := bodies[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = io.WriteString(w, body)
}

// fakeAccessKeyorix serves the Keyorix reads (project team-a=1 with environment prod=11, no
// roles, no machine identities) and records every other request as a write, answering 500.
type fakeAccessKeyorix struct {
	mu     sync.Mutex
	writes []string
}

func (f *fakeAccessKeyorix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		f.mu.Lock()
		f.writes = append(f.writes, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/projects":
		_, _ = io.WriteString(w, `{"data":{"projects":[{"id":1,"name":"team-a"}]}}`)
	case "/api/v1/projects/1/environments":
		_, _ = io.WriteString(w, `{"data":{"environments":[{"id":11,"name":"prod"}]}}`)
	case "/api/v1/projects/1/machine-identities":
		_, _ = io.WriteString(w, `{"data":{"machine_identities":[]}}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"not found"}`)
	}
}

func (f *fakeAccessKeyorix) recordedWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

// useAccessFlags points the shared plan/apply/audit-access flag variables at the fakes and
// restores them when the test ends.
func useAccessFlags(t *testing.T, vaultURL, keyorixURL string) {
	t.Helper()
	paAddr, paToken, paServer, paKeyorixTok = vaultURL, "vault-token", keyorixURL, "pat"
	t.Cleanup(func() {
		paAddr, paToken, paServer, paKeyorixTok = "", "", "", ""
		paK8sIssuer, paPathMap = "", nil
		aaPlanPath, aaCredentialsOut, aaJSON = "", "", false
	})
}

// writeReviewedPlan runs the plan-access pipeline against the fakes as they are now and writes
// the plan JSON a reviewer would approve.
func writeReviewedPlan(t *testing.T, vaultURL, keyorixURL, path string) {
	t.Helper()
	ctx := context.Background()
	vc, err := healthscan.New(ctx, healthscan.Config{Addr: vaultURL, Token: "vault-token"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	api, err := newAPIClient(keyorixURL, "pat")
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := buildFreshAccessPlan(ctx, vc, accesstarget.New(api), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := accessreport.WriteJSON(&buf, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"create"`) {
		t.Fatalf("reviewed plan has no create item, the drift test would prove nothing:\n%s", buf.String())
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// apply-access re-lists the KV tree and refuses, before SelectForApply/Apply run and before
// --credentials-out is opened, when the tree behind a reviewed default-convention grant changed
// since plan-access (here: kv1/team-a/prod/ appeared). The control run without drift shows the
// same harness does see writes and the credentials file, so the zero-writes assertion is not
// vacuous (REVIEW-3671-DEEP-1 finding 3).
func TestRunApplyAccess_CrossMountDriftWritesNothing(t *testing.T) {
	for _, drift := range []bool{true, false} {
		vault := &fakeAccessVault{}
		vsrv := httptest.NewServer(vault)
		keyorix := &fakeAccessKeyorix{}
		ksrv := httptest.NewServer(keyorix)
		useAccessFlags(t, vsrv.URL, ksrv.URL)
		dir := t.TempDir()
		aaPlanPath = filepath.Join(dir, "plan.json")
		aaCredentialsOut = filepath.Join(dir, "credentials.tsv")
		writeReviewedPlan(t, vsrv.URL, ksrv.URL, aaPlanPath)
		vault.setKV1HoldsTeamAProd(drift)

		var stdout, stderr bytes.Buffer
		applyAccessCmd.SetOut(&stdout)
		applyAccessCmd.SetErr(&stderr)
		applyAccessCmd.SetContext(context.Background())
		err := runApplyAccess(applyAccessCmd, nil)
		_, statErr := os.Stat(aaCredentialsOut)
		writes := keyorix.recordedWrites()
		vsrv.Close()
		ksrv.Close()

		if drift {
			if err == nil || !strings.Contains(err.Error(), "nothing was applied") || !strings.Contains(stderr.String(), "kv1/team-a/prod/") {
				t.Fatalf("drift: err=%v stderr=%q, want the cross-mount drift refusal naming kv1/team-a/prod/", err, stderr.String())
			}
			if len(writes) != 0 {
				t.Fatalf("drift: Keyorix received writes %v, want none", writes)
			}
			if !os.IsNotExist(statErr) {
				t.Fatalf("drift: --credentials-out was opened (stat err %v), want it never created", statErr)
			}
			continue
		}
		if len(writes) == 0 || statErr != nil {
			t.Fatalf("control (no drift): writes=%v credentials stat=%v err=%v, want apply to reach Keyorix and open --credentials-out", writes, statErr, err)
		}
	}
}

// auditOutput is audit-access's --json document.
type auditOutput struct {
	Complete *bool            `json:"complete"`
	Warnings []string         `json:"warnings"`
	Findings []map[string]any `json:"findings"`
}

func runAuditJSON(t *testing.T, vault *fakeAccessVault) (stdout, stderr string, err error) {
	t.Helper()
	vsrv := httptest.NewServer(vault)
	defer vsrv.Close()
	ksrv := httptest.NewServer(&fakeAccessKeyorix{})
	defer ksrv.Close()
	useAccessFlags(t, vsrv.URL, ksrv.URL)
	aaJSON = true
	var out, errOut bytes.Buffer
	auditAccessCmd.SetOut(&out)
	auditAccessCmd.SetErr(&errOut)
	auditAccessCmd.SetContext(context.Background())
	err = runAuditAccess(auditAccessCmd, nil)
	return out.String(), errOut.String(), err
}

func decodeAudit(t *testing.T, stdout string) auditOutput {
	t.Helper()
	var out auditOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("--json stdout is not the audit document: %v\n%s", err, stdout)
	}
	return out
}

// An input audit-access could not read (here: the policy list, so there are zero candidates)
// makes the audit incomplete: it must not report clean. It exits non-zero and --json says
// complete=false with the warning (REVIEW-3671-DEEP-1 finding 2).
func TestRunAuditAccess_UnreadableInputIsIncomplete(t *testing.T) {
	stdout, stderr, err := runAuditJSON(t, &fakeAccessVault{forbidden: map[string]bool{"LIST /v1/sys/policies/acl": true}})
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err=%v, want a non-nil 'incomplete' error when sys/policies/acl is unreadable", err)
	}
	out := decodeAudit(t, stdout)
	if out.Complete == nil || *out.Complete || !strings.Contains(strings.Join(out.Warnings, "\n"), "sys/policies/acl") {
		t.Fatalf("--json = %+v, want complete=false and a warning naming sys/policies/acl", out)
	}
	if strings.Contains(stderr, "no migrated grant is wider") {
		t.Fatalf("stderr reports a clean audit although an input was unreadable:\n%s", stderr)
	}

	// The same Vault with everything readable is a complete, clean audit.
	stdout, _, err = runAuditJSON(t, &fakeAccessVault{})
	out = decodeAudit(t, stdout)
	if err != nil || out.Complete == nil || !*out.Complete || len(out.Findings) != 0 {
		t.Fatalf("readable inputs: err=%v --json=%+v, want a complete, clean audit", err, out)
	}

	// An unlistable KV mount hides nothing: the stanzas it could affect become cross-mount
	// candidates (checked against Keyorix), so it is a warning and the audit stays complete.
	stdout, _, err = runAuditJSON(t, &fakeAccessVault{forbidden: map[string]bool{"LIST /v1/kv1": true}})
	out = decodeAudit(t, stdout)
	if err != nil || out.Complete == nil || !*out.Complete || !strings.Contains(strings.Join(out.Warnings, "\n"), "kv1/") {
		t.Fatalf("unlistable kv1/: err=%v --json=%+v, want a complete audit with a warning naming kv1/", err, out)
	}
}

// Kubernetes auth roles are audited only with --k8s-issuer (v0.96.x created Kubernetes
// identities only with it). Without the flag, audit-access says it skipped them instead of
// staying silent.
func TestRunAuditAccess_KubernetesRolesWithoutIssuerWarns(t *testing.T) {
	vault := &fakeAccessVault{extra: map[string]string{
		"/v1/sys/auth":                      `{"data":{"approle/":{"type":"approle"},"kubernetes/":{"type":"kubernetes"}}}`,
		"LIST /v1/auth/kubernetes/role":     `{"data":{"keys":["deployer"]}}`,
		"/v1/auth/kubernetes/role/deployer": `{"data":{"bound_service_account_names":["deployer"],"bound_service_account_namespaces":["prod"],"token_policies":["team-a-prod-ro"]}}`,
	}}
	stdout, stderr, err := runAuditJSON(t, vault)
	if err != nil {
		t.Fatalf("err=%v, want a clean audit (the note does not make it incomplete)", err)
	}
	if out := decodeAudit(t, stdout); !strings.Contains(strings.Join(out.Warnings, "\n"), "--k8s-issuer") || !strings.Contains(stderr, "--k8s-issuer") {
		t.Fatalf("--json warnings=%v stderr=%q, want a note that Kubernetes roles were not audited without --k8s-issuer", out.Warnings, stderr)
	}
}
