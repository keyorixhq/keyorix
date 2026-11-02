package deploy

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// HELM-PILOT-TAILS-2: render matrix. The chart must render, pass kubeconform (when it is
// on PATH and can fetch schemas; otherwise that subtest is SKIPPED, see kubeconformCheck) and keep
// every credential out of a ConfigMap for the topologies operators actually run
// (1 and 2 replicas, bundled and external database, keys PVC and keys Secret, with
// the NetworkPolicy, Ingress, secure baseline and an existing auth Secret), and refuse
// the combinations that cannot work.
//
// Replicas > 1 is only valid in Secret mode: a ReadWriteMany keys PVC is refused by
// design (keyorix.server.replicas), so the RWX variant is a one-replica case and the
// two-replica RWX case is in the refusals below.

const (
	matrixMaster   = "SENTINEL-master-password-1f3a"
	matrixAdmin    = "SENTINEL-bootstrap-pw-9c2b"
	matrixPGPass   = "SENTINEL-pg-password-77d0"
	matrixExtPass  = "SENTINEL-ext-db-password-4e8a"
	matrixCredFlag = "auth.masterPassword=" + matrixMaster
)

var matrixSentinels = []string{matrixMaster, matrixAdmin, matrixPGPass, matrixExtPass}

var matrixExternalDB = []string{
	"postgresql.enabled=false", "externalDatabase.host=db.example",
	"externalDatabase.password=" + matrixExtPass,
}

var matrixOverlay = []string{
	"networkPolicy.enabled=true", "ingress.enabled=true", "ingress.hosts[0].host=kx.example",
	"secureBaseline.enabled=true",
}

func matrixRender(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	args := []string{"template", "kx", chartWithValues(t, "")}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, temp chart path and test flags
	return string(out), err
}

func decodeAll(t *testing.T, manifest string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			break
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

// kubeconformCheck runs kubeconform (-strict, Kubernetes 1.29.0) over the manifest. It
// skips (not passes) when the binary is not on PATH or cannot fetch the schemas, so a run
// without it reports SKIP instead of a green test that validated nothing. Call it from its
// own subtest: the skip then marks only the schema check, not the render assertions.
//
// This is NOT the CI chart job's kubeconform: that job installs ./kubeconform in the
// workspace and validates its own renders, and it is not on PATH for the Go test jobs, so
// the Go test-suite normally skips this check.
func kubeconformCheck(t *testing.T, manifest string) {
	t.Helper()
	bin, err := exec.LookPath("kubeconform")
	if err != nil {
		t.Skip("kubeconform not installed: schema validation not run")
	}
	cmd := exec.Command(bin, "-strict", "-summary", "-kubernetes-version", "1.29.0") //nolint:gosec // resolved binary, fixed flags
	cmd.Stdin = strings.NewReader(manifest)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if strings.Contains(out.String(), "could not find schema") || strings.Contains(out.String(), "failed downloading") {
			t.Skipf("kubeconform could not fetch schemas (offline), schema validation not run: %s", strings.TrimSpace(out.String()))
		}
		t.Errorf("kubeconform: %v\n%s", err, out.String())
	}
}

func TestHelmRenderMatrix(t *testing.T) {
	requireHelm(t)
	type variant struct {
		name string
		sets []string
	}
	cat := func(parts ...[]string) []string {
		var all []string
		for _, p := range parts {
			all = append(all, p...)
		}
		return all
	}
	creds := []string{matrixCredFlag, "auth.adminPassword=" + matrixAdmin, "postgresql.auth.password=" + matrixPGPass}
	for _, v := range []variant{
		{"1 replica, bundled PostgreSQL, keys PVC", cat(creds, matrixOverlay)},
		{"1 replica, bundled PostgreSQL, RWX keys PVC", cat(creds, matrixOverlay, []string{"server.keysPersistence.accessMode=ReadWriteMany"})},
		{"1 replica, external database", cat(creds, matrixOverlay, matrixExternalDB)},
		{"1 replica, existing auth Secret", cat(matrixOverlay, []string{"auth.existingSecret=kx-auth"})},
		{"2 replicas, bundled PostgreSQL, keys Secret", cat(creds, matrixOverlay, keysSecretSets, []string{"server.replicas=2"})},
		{"2 replicas, external database, keys Secret", cat(creds, matrixOverlay, matrixExternalDB, keysSecretSets, []string{"server.replicas=2"})},
		{"2 replicas, external database, existing auth Secret", cat(matrixOverlay, matrixExternalDB, keysSecretSets, []string{"server.replicas=2", "auth.existingSecret=kx-auth"})},
	} {
		t.Run(v.name, func(t *testing.T) {
			out, err := matrixRender(t, v.sets...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			docs := decodeAll(t, out)
			if findDoc(docs, "Deployment", "server") == nil {
				t.Fatal("no server Deployment rendered")
			}
			for _, kind := range []string{"NetworkPolicy", "Ingress"} {
				found := false
				for _, d := range docs {
					found = found || d["kind"] == kind
				}
				if !found {
					t.Errorf("%s was enabled but not rendered", kind)
				}
			}
			// No credential value may sit in a ConfigMap (Secrets are the place for it).
			for _, d := range docs {
				if d["kind"] != "ConfigMap" {
					continue
				}
				b, err := yaml.Marshal(d)
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range matrixSentinels {
					if strings.Contains(string(b), s) {
						t.Errorf("ConfigMap %v contains the credential %q:\n%s", nested(d, "metadata", "name"), s, b)
					}
				}
			}
			t.Run("kubeconform", func(t *testing.T) { kubeconformCheck(t, out) })
		})
	}
}

// Fail-closed: the render is refused, with the chart's own message.
func TestHelmRenderMatrix_RefusalsSayWhy(t *testing.T) {
	requireHelm(t)
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{"no master password", []string{"postgresql.auth.password=x"}, "auth.masterPassword is required (or set auth.existingSecret)"},
		{"no database password", []string{"auth.masterPassword=x"}, "A database password is required"},
		{"2 replicas without Secret mode", []string{matrixCredFlag, "postgresql.auth.password=x", "server.replicas=2"}, "needs Secret mode (server.keysSecret.enabled=true"},
		{"2 replicas on an RWX keys PVC", []string{matrixCredFlag, "postgresql.auth.password=x", "server.replicas=2", "server.keysPersistence.accessMode=ReadWriteMany"}, "a shared writable keys volume is not a supported HA mode"},
		{"secure baseline Secret without the baseline", []string{matrixCredFlag, "postgresql.auth.password=x", "secureBaseline.enabled=false", "secureBaseline.existingSecret=s"}, "secureBaseline.existingSecret is set but secureBaseline.enabled is false"},
		{"ingress without the web UI", []string{matrixCredFlag, "postgresql.auth.password=x", "ingress.enabled=true", "web.enabled=false"}, "ingress.enabled requires web.enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := matrixRender(t, tc.sets...)
			if err == nil {
				t.Fatalf("render succeeded, want a refusal containing %q", tc.want)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("refusal does not contain %q:\n%s", tc.want, out)
			}
		})
	}
}
