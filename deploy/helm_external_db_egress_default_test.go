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
//
// The check is deliberately wider than "a rule naming the database": ANY egress rule that
// can reach TCP/5432 fails, whether or not it has a `to` (no `to` allows every destination)
// and whether or not it lists `ports` (no ports allows every port).
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
		for _, r := range reachingTCP5432(np) {
			t.Errorf("default values must not carry an egress rule that can reach TCP/5432 (changing that is a product decision): %v", r)
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

// reachingTCP5432 returns the egress rules of the NetworkPolicy np that can reach TCP/5432.
// A rule reaches it when it has no ports (every port), when a port entry has no port
// (every port of that protocol), when a TCP entry names 5432 or a range containing it, or
// when the port is a name (resolved on the destination pod, so it cannot be ruled out).
// Only an explicit non-TCP protocol, or a different number, clears a port entry.
func reachingTCP5432(np map[string]any) []any {
	var hit []any
	for _, r := range npSlice(npNested(np, "spec", "egress")) {
		rule, _ := r.(map[string]any)
		ports := npSlice(rule["ports"])
		if len(ports) == 0 {
			hit = append(hit, r)
			continue
		}
		for _, p := range ports {
			pm, _ := p.(map[string]any)
			if proto, ok := pm["protocol"].(string); ok && proto != "TCP" {
				continue
			}
			port, ok := pm["port"]
			if !ok {
				hit = append(hit, r)
				break
			}
			lo, isNum := port.(int)
			if !isNum {
				hit = append(hit, r) // named port, or a type we do not know: fail closed
				break
			}
			hi := lo
			if e, ok := pm["endPort"].(int); ok {
				hi = e
			}
			if lo <= 5432 && 5432 <= hi {
				hit = append(hit, r)
				break
			}
		}
	}
	return hit
}

// The check above is only worth having if it goes red: render the chart with a deliberately
// bad values overlay (testdata/helm-egress-*.yaml; the chart under test is not edited) and
// require it to flag each permissive shape, and to stay quiet on the green control.
func TestHelmDefaultEgressCheckFlagsPermissiveRules(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")
	for _, tc := range []struct {
		fixture string
		flagged bool
	}{
		{"helm-egress-permissive-port-no-to.yaml", true},
		{"helm-egress-permissive-no-ports.yaml", true},
		{"helm-egress-permissive-port-with-to.yaml", true},
		{"helm-egress-safe-other-port.yaml", false},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			args := []string{"template", "kx", chart, "--set", "auth.masterPassword=x", "--set", "postgresql.enabled=false",
				"--set", "externalDatabase.host=db.example", "--set", "externalDatabase.password=x", "-f", filepath.Join("testdata", tc.fixture)}
			out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, temp chart path and fixture path
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			np := npFindNamed(decodeAll(t, string(out)), "NetworkPolicy", "kx-keyorix-server")
			if np == nil {
				t.Fatal("no server NetworkPolicy rendered")
			}
			if got := reachingTCP5432(np); (len(got) > 0) != tc.flagged {
				t.Errorf("flagged=%v, want %v; rules reaching TCP/5432: %v", len(got) > 0, tc.flagged, got)
			}
		})
	}
}
