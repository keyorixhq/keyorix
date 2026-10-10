// deploy_hardening_test.go -- DEPLOY-1 guard: the container-hardening baseline
// of the two shipped deployment paths (docker-compose.yml and the Helm chart
// deploy/helm/keyorix) is asserted from the files themselves, so it cannot
// drift back to a root / writable-rootfs / all-capabilities workload unnoticed.
//
// Baseline (every long-running workload): non-root, read-only root filesystem,
// capabilities dropped to ALL (the only allowed add-back is NET_BIND_SERVICE for
// ports 80/443), no privilege escalation, no privileged mode. For the chart also
// seccomp RuntimeDefault and no service-account token. Docker applies its
// default seccomp profile unless it is explicitly disabled, so for compose the
// test asserts it is NOT disabled.
//
// What this does NOT cover: whether the workloads actually start under these
// settings (that was proven by deploying on the bench VM, see the PR), image
// contents, or secrets handling (env vs file mounts needs server *_FILE support).
//
// The chart half needs `helm` and skips cleanly without it; CI's "helm-chart"
// job has it (see password_policy_helm_chart_test.go).
package hardening

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

type m = map[string]any

func asMap(v any) m {
	if x, ok := v.(m); ok {
		return x
	}
	return m{}
}

func asList(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}

func hasString(list any, want string) bool {
	for _, e := range asList(list) {
		if s, ok := e.(string); ok && strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// ---- compose -------------------------------------------------------------

func TestCompose_ServicesAreHardened(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	services := asMap(doc["services"])
	for _, name := range []string{"postgres", "backend", "web", "caddy"} {
		svc, ok := services[name].(m)
		if !ok {
			t.Fatalf("docker-compose.yml: service %q missing -- update this guard if it was renamed", name)
		}
		if svc["read_only"] != true {
			t.Errorf("%s: read_only must be true (writable paths belong on tmpfs/volumes)", name)
		}
		if !hasString(svc["cap_drop"], "ALL") {
			t.Errorf("%s: cap_drop must contain ALL", name)
		}
		for _, c := range asList(svc["cap_add"]) {
			if s, _ := c.(string); s != "NET_BIND_SERVICE" {
				t.Errorf("%s: cap_add %v -- only NET_BIND_SERVICE may be added back", name, c)
			}
		}
		if !hasString(svc["security_opt"], "no-new-privileges:true") {
			t.Errorf("%s: security_opt must contain no-new-privileges:true", name)
		}
		for _, o := range asList(svc["security_opt"]) {
			if s, _ := o.(string); strings.Contains(s, "seccomp") || strings.Contains(s, "apparmor=unconfined") {
				t.Errorf("%s: security_opt %q disables Docker's default confinement", name, s)
			}
		}
		if svc["privileged"] == true {
			t.Errorf("%s: privileged must not be set", name)
		}
	}
	// postgres' image would otherwise start as root and drop privileges itself,
	// which needs CAP_SETUID/SETGID/CHOWN; running as the image's own uid avoids that.
	pg := asMap(services["postgres"])
	if u, _ := pg["user"].(string); u == "" || u == "0" || strings.HasPrefix(u, "0:") || u == "root" {
		t.Errorf("postgres: user must be a non-root uid:gid, got %q", u)
	}
}

// ---- helm chart ----------------------------------------------------------

func renderChart(t *testing.T) []m {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart hardening check")
	}
	chart := filepath.Join(repoRoot(), "deploy", "helm", "keyorix")
	cmd := exec.Command("helm", "template", "kx", chart, //nolint:gosec // fixed binary and chart path
		"--set", "auth.masterPassword=x",
		"--set", "postgresql.auth.password=x",
		"--set-string", "auth.adminPassword=0123456789abcdef0123",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var docs []m
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var d m
		if err := dec.Decode(&d); err != nil {
			break
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func TestHelmChart_WorkloadsAreHardened(t *testing.T) {
	docs := renderChart(t)
	seen := map[string]bool{}
	for _, d := range docs {
		if d["kind"] != "Deployment" {
			continue
		}
		name, _ := asMap(d["metadata"])["name"].(string)
		comp, _ := asMap(asMap(d["metadata"])["labels"])["app.kubernetes.io/component"].(string)
		seen[comp] = true
		if ann := asMap(asMap(d["metadata"])["annotations"]); ann != nil {
			for k, v := range ann {
				if s, _ := v.(string); strings.HasPrefix(k, "checkov.io/skip") && strings.Contains(s, "CKV_K8S_22") {
					t.Errorf("%s: %s=%q -- the read-only-rootfs exemption must not come back", name, k, s)
				}
			}
		}
		spec := asMap(asMap(asMap(d["spec"])["template"])["spec"])
		pod := asMap(spec["securityContext"])
		if pod["runAsNonRoot"] != true {
			t.Errorf("%s: pod runAsNonRoot must be true", name)
		}
		if uid, _ := pod["runAsUser"].(int); uid == 0 {
			t.Errorf("%s: pod runAsUser must be set and non-zero", name)
		}
		if asMap(pod["seccompProfile"])["type"] != "RuntimeDefault" {
			t.Errorf("%s: pod seccompProfile.type must be RuntimeDefault", name)
		}
		if spec["automountServiceAccountToken"] != false {
			t.Errorf("%s: automountServiceAccountToken must be false", name)
		}
		if comp == "server" {
			// keys PVC must be writable by the server uid under a root-owned provisioner.
			if pod["fsGroup"] != pod["runAsUser"] || pod["fsGroup"] == nil {
				t.Errorf("%s: server pod fsGroup (%v) must equal runAsUser (%v) so the keys PVC is writable", name, pod["fsGroup"], pod["runAsUser"])
			}
		}
		volumes := map[string]m{}
		for _, v := range asList(spec["volumes"]) {
			vm := asMap(v)
			n, _ := vm["name"].(string)
			volumes[n] = vm
		}
		for _, c := range asList(spec["containers"]) {
			cm := asMap(c)
			cname, _ := cm["name"].(string)
			sc := asMap(cm["securityContext"])
			if sc["allowPrivilegeEscalation"] != false {
				t.Errorf("%s/%s: allowPrivilegeEscalation must be false", name, cname)
			}
			if sc["readOnlyRootFilesystem"] != true {
				t.Errorf("%s/%s: readOnlyRootFilesystem must be true", name, cname)
			}
			if sc["privileged"] == true {
				t.Errorf("%s/%s: privileged must not be set", name, cname)
			}
			caps := asMap(sc["capabilities"])
			if !hasString(caps["drop"], "ALL") {
				t.Errorf("%s/%s: capabilities.drop must contain ALL", name, cname)
			}
			for _, a := range asList(caps["add"]) {
				if s, _ := a.(string); s != "NET_BIND_SERVICE" {
					t.Errorf("%s/%s: capabilities.add %v -- only NET_BIND_SERVICE may be added back", name, cname, a)
				}
			}
			// A read-only rootfs only works if every other write target is a mounted volume;
			// every mount must reference a declared volume (catches a dropped emptyDir).
			for _, vmnt := range asList(cm["volumeMounts"]) {
				vn, _ := asMap(vmnt)["name"].(string)
				if _, ok := volumes[vn]; !ok {
					t.Errorf("%s/%s: volumeMount %q has no matching volume", name, cname, vn)
				}
			}
		}
	}
	for _, want := range []string{"server", "web", "postgresql"} {
		if !seen[want] {
			t.Errorf("no %q Deployment rendered -- the guard would be vacuous; update it if the component was renamed", want)
		}
	}
}
