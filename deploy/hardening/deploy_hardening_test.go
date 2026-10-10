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
// contents. Secrets handling (DEPLOY-2) IS covered statically -- no credential in any
// container environment, *_FILE variables pointing at mounted secret files -- but that
// the files are actually readable by the container user was proven on the bench.
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

func nonRootUser(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") {
		return false
	}
	return true
}

func volumeNames(svc m) []string {
	var out []string
	for _, v := range asList(svc["volumes"]) {
		if s, ok := v.(string); ok {
			// "caddy_data:/data" or "./file:/path:ro"
			if src, _, found := strings.Cut(s, ":"); found && !strings.HasPrefix(src, ".") && !strings.HasPrefix(src, "/") {
				out = append(out, src+":"+strings.Split(s, ":")[1])
			}
		}
	}
	return out
}

// DEPLOY-2 decision 3: caddy runs as a non-root user with only NET_BIND_SERVICE.
// Its /data and /config volumes were created root-owned by the previous layout, so
// a one-shot caddy-init service chowns them first. The init step is the only root
// service and may add back only CHOWN; the guard also pins that caddy waits for it
// to COMPLETE (not merely start) and that both mount the very same volumes.
func TestCompose_CaddyRunsNonRootAfterOneShotInit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	services := asMap(doc["services"])
	caddy, ok := services["caddy"].(m)
	if !ok {
		t.Fatal("caddy service missing")
	}
	user, _ := caddy["user"].(string)
	if !nonRootUser(user) {
		t.Errorf("caddy: user must be a non-root uid:gid, got %q", user)
	}
	if !strings.Contains(user, ":") {
		t.Errorf("caddy: user %q must name uid:gid explicitly so the init step can chown to it", user)
	}
	if len(asList(caddy["cap_add"])) != 1 || !hasString(caddy["cap_add"], "NET_BIND_SERVICE") {
		t.Errorf("caddy: cap_add must be exactly [NET_BIND_SERVICE], got %v", caddy["cap_add"])
	}

	initSvc, ok := services["caddy-init"].(m)
	if !ok {
		t.Fatal("caddy-init service missing: an existing root-owned caddy_data/caddy_config volume would make non-root caddy fail")
	}
	if p := asList(initSvc["profiles"]); len(p) != 1 || !hasString(p, "tls") {
		t.Errorf("caddy-init: profiles must be [tls] like caddy, got %v", initSvc["profiles"])
	}
	if initSvc["restart"] != "no" {
		t.Errorf("caddy-init: restart must be \"no\" (one-shot), got %v", initSvc["restart"])
	}
	if initSvc["read_only"] != true {
		t.Error("caddy-init: read_only must be true")
	}
	if !hasString(initSvc["cap_drop"], "ALL") {
		t.Error("caddy-init: cap_drop must contain ALL")
	}
	if len(asList(initSvc["cap_add"])) != 1 || !hasString(initSvc["cap_add"], "CHOWN") {
		t.Errorf("caddy-init: cap_add must be exactly [CHOWN], got %v", initSvc["cap_add"])
	}
	if !hasString(initSvc["security_opt"], "no-new-privileges:true") {
		t.Error("caddy-init: security_opt must contain no-new-privileges:true")
	}
	if initSvc["privileged"] == true {
		t.Error("caddy-init: privileged must not be set")
	}
	joined := ""
	for _, key := range []string{"entrypoint", "command"} {
		for _, c := range asList(initSvc[key]) {
			s, _ := c.(string)
			joined += s + " "
		}
	}
	if !strings.Contains(joined, "chown") || !strings.Contains(joined, user) {
		t.Errorf("caddy-init: entrypoint/command %q must chown the volumes to caddy's user %q", joined, user)
	}
	if !strings.Contains(joined, "/data") || !strings.Contains(joined, "/config") {
		t.Errorf("caddy-init: %q must chown both /data and /config", joined)
	}
	if initSvc["network_mode"] != "none" {
		t.Errorf("caddy-init: network_mode must be none, got %v", initSvc["network_mode"])
	}

	dep := asMap(asMap(caddy["depends_on"])["caddy-init"])
	if dep["condition"] != "service_completed_successfully" {
		t.Errorf("caddy: depends_on caddy-init must use condition service_completed_successfully, got %v", dep["condition"])
	}
	cv, iv := volumeNames(caddy), volumeNames(initSvc)
	for _, want := range []string{"caddy_data:/data", "caddy_config:/config"} {
		found := false
		for _, v := range cv {
			found = found || v == want
		}
		if !found {
			t.Errorf("caddy: volume %s missing", want)
		}
		found = false
		for _, v := range iv {
			found = found || v == want
		}
		if !found {
			t.Errorf("caddy-init: volume %s missing -- it must chown the same volumes caddy uses", want)
		}
	}
}

// secretish reports whether an environment variable name carries a credential
// (so its value must come from a file, never from the container environment).
func secretish(name string) bool {
	if strings.HasSuffix(name, "_FILE") {
		return false
	}
	for _, s := range []string{"PASSWORD", "TOKEN", "SECRET", "API_KEY"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// DEPLOY-2 decision 1: no secret value in any container's environment. Each
// credential reaches its container as a Docker secrets file named by a *_FILE
// variable (server: internal/secretenv; postgres: POSTGRES_PASSWORD_FILE;
// entrypoint.sh for the admin bootstrap).
func TestCompose_SecretsAreFilesNotEnv(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc m
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	top := asMap(doc["secrets"])
	for name, def := range top {
		if f, _ := asMap(def)["file"].(string); f == "" {
			t.Errorf("top-level secret %q must be file-based, got %v", name, def)
		}
	}
	usedAny := false
	for svcName, v := range asMap(doc["services"]) {
		svc := asMap(v)
		mounted := map[string]bool{}
		for _, s := range asList(svc["secrets"]) {
			if n, ok := s.(string); ok {
				mounted[n] = true
				if _, defined := top[n]; !defined {
					t.Errorf("%s: secret %q is not defined at top level", svcName, n)
				}
			}
		}
		usesFile := false
		for k, val := range asMap(svc["environment"]) {
			if secretish(k) {
				t.Errorf("%s: environment variable %s carries a credential; use %s_FILE with a Docker secret", svcName, k, k)
			}
			if strings.HasSuffix(k, "_FILE") {
				usesFile = true
				usedAny = true
				p, _ := val.(string)
				base := strings.TrimPrefix(p, "/run/secrets/")
				if base == p || !mounted[base] {
					t.Errorf("%s: %s=%q must point at /run/secrets/<name> of a secret the service mounts (%v)", svcName, k, p, mounted)
				}
			}
		}
		if usesFile {
			gid := false
			for _, g := range asList(svc["group_add"]) {
				if s, _ := g.(string); strings.Contains(s, "KEYORIX_SECRETS_GID") {
					gid = true
				}
			}
			if !gid {
				t.Errorf("%s: reads secret files but does not join KEYORIX_SECRETS_GID via group_add (Compose ignores secret uid/gid/mode, so the 0640 host file would be unreadable)", svcName)
			}
		}
	}
	if !usedAny {
		t.Error("no *_FILE variable found in docker-compose.yml -- the guard would be vacuous")
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

// DEPLOY-2 decision 1 for the chart: no credential in a container's environment
// (neither as a literal nor via secretKeyRef). Each reaches the pod as a file from
// a Secret volume (defaultMode <= 0440, read-only mount) named by a *_FILE variable.
func TestHelmChart_SecretsAreMountedFilesNotEnv(t *testing.T) {
	docs := renderChart(t)
	filesSeen := 0
	for _, d := range docs {
		if d["kind"] != "Deployment" {
			continue
		}
		name, _ := asMap(d["metadata"])["name"].(string)
		spec := asMap(asMap(asMap(d["spec"])["template"])["spec"])
		volumes := map[string]m{}
		for _, v := range asList(spec["volumes"]) {
			vm := asMap(v)
			n, _ := vm["name"].(string)
			volumes[n] = vm
		}
		for _, c := range asList(spec["containers"]) {
			cm := asMap(c)
			cname, _ := cm["name"].(string)
			mounts := map[string]m{}
			for _, mnt := range asList(cm["volumeMounts"]) {
				mm := asMap(mnt)
				p, _ := mm["mountPath"].(string)
				mounts[p] = mm
			}
			for _, e := range asList(cm["env"]) {
				em := asMap(e)
				en, _ := em["name"].(string)
				if _, ok := asMap(em["valueFrom"])["secretKeyRef"]; ok {
					t.Errorf("%s/%s: env %s uses secretKeyRef -- mount the Secret as a file and use %s_FILE", name, cname, en, en)
				}
				if secretish(en) {
					t.Errorf("%s/%s: env %s carries a credential; use %s_FILE", name, cname, en, en)
				}
				if !strings.HasSuffix(en, "_FILE") {
					continue
				}
				filesSeen++
				val, _ := em["value"].(string)
				var mount m
				var mountPath string
				for p, mm := range mounts {
					if strings.HasPrefix(val, strings.TrimSuffix(p, "/")+"/") {
						mount, mountPath = mm, p
					}
				}
				if mount == nil {
					t.Errorf("%s/%s: %s=%q is not under any volumeMount", name, cname, en, val)
					continue
				}
				if mount["readOnly"] != true {
					t.Errorf("%s/%s: secret mount %s must be readOnly", name, cname, mountPath)
				}
				vol := volumes[mount["name"].(string)]
				var defaultMode any
				if sec := asMap(vol["secret"]); len(sec) > 0 {
					defaultMode = sec["defaultMode"]
				} else if prj := asMap(vol["projected"]); len(prj) > 0 {
					defaultMode = prj["defaultMode"]
				} else {
					t.Errorf("%s/%s: %s is not backed by a secret/projected volume", name, cname, en)
					continue
				}
				if dm, ok := defaultMode.(int); !ok || dm == 0 || dm&^0o440 != 0 {
					t.Errorf("%s/%s: secret volume defaultMode must be set and <= 0440 (got %v)", name, cname, defaultMode)
				}
			}
		}
	}
	if filesSeen == 0 {
		t.Error("no *_FILE env found in the rendered chart -- the guard would be vacuous")
	}
}
