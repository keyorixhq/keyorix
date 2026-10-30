package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// HELM-EGRESS-DB-DEFAULT: pins today's behaviour, it does not choose it. With an
// external database, the default NetworkPolicy (networkPolicy.enabled and
// networkPolicy.egress.enabled are both true) gives the server pod NO egress rule for
// the database unless networkPolicy.egress.databaseTo or extraRules names it, so the
// connection is denied. The chart says so in NOTES.txt (#3307). Whether the default
// should change is a product decision (NEEDS ANDREI); if it does, this test must
// change in the same diff, which is the point of having it.
func TestHelmExternalDatabaseDefaultNetworkPolicyDeniesDB(t *testing.T) {
	requireHelm(t)
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	kubeconfig := fakeKube(t, nil)
	ext := []string{"auth.masterPassword=x", "postgresql.enabled=false", "externalDatabase.host=db.example", "externalDatabase.password=x", "externalDatabase.port=5432"}

	// notes renders NOTES.txt the way helm_notes_admin_test.go does (helm install --dry-run=client).
	notes := func(t *testing.T, sets ...string) string {
		t.Helper()
		args := []string{"install", "kx", chart, "--dry-run=client", "--disable-openapi-validation", "--namespace", "kx-ns"}
		for _, s := range append(append([]string{}, ext...), sets...) {
			args = append(args, "--set", s)
		}
		cmd := exec.Command("helm", args...) //nolint:gosec // fixed binary, chart path and test flags
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helm install --dry-run=client: %v\n%s", err, out)
		}
		_, after, ok := strings.Cut(string(out), "\nNOTES:\n")
		if !ok {
			t.Fatalf("no NOTES section in the dry-run output:\n%s", out)
		}
		return after
	}
	const warning = "the database is external, but\n    networkPolicy.egress.databaseTo is empty: the server pod is denied egress to\n    db.example:5432 unless networkPolicy.egress.extraRules allows it."

	t.Run("defaults: no rule for the database, and NOTES says so", func(t *testing.T) {
		chartDir := chartWithValues(t, "")
		docs := helmTemplateDocs(t, chartDir, ext[1:]...)
		np := npFindNamed(docs, "NetworkPolicy", "kx-keyorix-server")
		if np == nil {
			t.Fatal("the default install must render the server NetworkPolicy")
		}
		for _, r := range npSlice(npNested(np, "spec", "egress")) {
			for _, p := range npSlice(r.(map[string]any)["ports"]) {
				if p.(map[string]any)["port"] == 5432 && r.(map[string]any)["to"] != nil {
					t.Errorf("default values must not carry an egress rule for the external database (changing that is a product decision): %v", r)
				}
			}
		}
		if n := notes(t); !strings.Contains(n, warning) {
			t.Errorf("NOTES.txt must warn that the external database is denied egress by default:\n%s", n)
		}
	})
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{"databaseTo given", []string{"networkPolicy.egress.databaseTo[0].ipBlock.cidr=10.20.0.0/24"}},
		{"extraRules given", []string{"networkPolicy.egress.extraRules[0].to[0].ipBlock.cidr=10.20.0.5/32"}},
		{"egress restriction off", []string{"networkPolicy.egress.enabled=false"}},
		{"NetworkPolicy off", []string{"networkPolicy.enabled=false"}},
	} {
		t.Run(tc.name+": no warning", func(t *testing.T) {
			if n := notes(t, tc.sets...); strings.Contains(n, "the database is external, but") {
				t.Errorf("the warning must appear only when the database is actually denied:\n%s", n)
			}
		})
	}
	t.Run("bundled PostgreSQL: no warning", func(t *testing.T) {
		args := []string{"install", "kx", chart, "--dry-run=client", "--disable-openapi-validation", "--namespace", "kx-ns",
			"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
		cmd := exec.Command("helm", args...) //nolint:gosec // fixed binary, chart path and test flags
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helm install --dry-run=client: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "the database is external, but") {
			t.Errorf("bundled PostgreSQL must not get the external-database warning:\n%s", out)
		}
	})
}
