package deploy

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// HELM-WEB-PROBES-1 (follow-up to #3460 / #3871): the chart's web pod used to
// point readiness AND liveness at a static `return 200` /health, so it stayed
// Ready while the backend Service was down. Liveness must be a static location
// (a dead backend must not restart nginx); readiness must proxy to the server
// Service so the pod goes NotReady (not restarted) when the backend is down.
//
// Checks the RENDERED Deployment and ConfigMap. Skips without helm, like the
// other chart render tests; CI's chart jobs have it. The real-nginx container
// check is pending the e2e VM.

func helmRenderWeb(t *testing.T, template string, extra ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart web probe check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	args := []string{"template", "kx", chart, "-s", "templates/" + template,
		"--set", "web.enabled=true", "--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
	args = append(args, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary and chart path
	if err != nil {
		t.Fatalf("helm template %s: %v\n%s", template, err, out)
	}
	return string(out)
}

// webProbePaths returns the readiness and liveness httpGet paths of the web
// container in the rendered Deployment.
func webProbePaths(t *testing.T, rendered string) (readiness, liveness string) {
	t.Helper()
	var dep struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name           string `yaml:"name"`
						ReadinessProbe struct {
							HTTPGet struct {
								Path string `yaml:"path"`
							} `yaml:"httpGet"`
						} `yaml:"readinessProbe"`
						LivenessProbe struct {
							HTTPGet struct {
								Path string `yaml:"path"`
							} `yaml:"httpGet"`
						} `yaml:"livenessProbe"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(rendered), &dep); err != nil {
		t.Fatalf("parse rendered web Deployment: %v", err)
	}
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "web" {
			return c.ReadinessProbe.HTTPGet.Path, c.LivenessProbe.HTTPGet.Path
		}
	}
	t.Fatalf("rendered web Deployment has no container named web:\n%s", rendered)
	return "", ""
}

// nginxExactLocation returns the body of `location = <path> {` (brace-balanced,
// first match) from the rendered nginx.conf.
func nginxExactLocation(conf, path string) (string, bool) {
	re := regexp.MustCompile(`(?m)^\s*location\s*=\s*` + regexp.QuoteMeta(path) + `\s*\{`)
	loc := re.FindStringIndex(conf)
	if loc == nil {
		return "", false
	}
	depth := 1
	for i := loc[1]; i < len(conf); i++ {
		switch conf[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return conf[loc[1]:i], true
			}
		}
	}
	return "", false
}

func TestHelmWebProbesLivenessStaticReadinessProxiesBackend(t *testing.T) {
	readiness, liveness := webProbePaths(t, helmRenderWeb(t, "web-deployment.yaml"))
	conf := helmRenderWeb(t, "web-config.yaml")

	// (a) the two probes must differ.
	if readiness == "" || liveness == "" {
		t.Fatalf("web probes need httpGet paths (readiness=%q liveness=%q)", readiness, liveness)
	}
	if readiness == liveness {
		t.Errorf("web readiness and liveness both probe %q; liveness must be a static location, readiness the backend-aware one", readiness)
	}

	// (b) the liveness path is a static location: answers itself, never proxies.
	live, ok := nginxExactLocation(conf, liveness)
	switch {
	case !ok:
		t.Errorf("liveness path %q has no `location = %s` block in the rendered nginx.conf", liveness, liveness)
	case strings.Contains(live, "proxy_pass"):
		t.Errorf("liveness location %s proxies to a backend: a backend outage would restart the web pod:\n%s", liveness, live)
	case !strings.Contains(live, "return 200"):
		t.Errorf("liveness location %s must be a static `return 200`:\n%s", liveness, live)
	}

	// (c) the readiness path proxies to the server Service, the same upstream
	// the API location uses.
	ready, ok := nginxExactLocation(conf, readiness)
	if !ok {
		t.Fatalf("readiness path %q has no `location = %s` block in the rendered nginx.conf", readiness, readiness)
	}
	if !strings.Contains(ready, "proxy_pass") {
		t.Errorf("readiness location %s must proxy to the server Service:\n%s", readiness, ready)
	}
	if strings.Contains(ready, "return ") {
		t.Errorf("readiness location %s must not answer statically:\n%s", readiness, ready)
	}
	// The same upstream as the /api proxy: server Service name and port.
	apiPass := regexp.MustCompile(`proxy_pass\s+(https?://[^\s;/]+)`).FindStringSubmatch(conf)
	readyPass := regexp.MustCompile(`proxy_pass\s+(https?://[^\s;/]+)(/\S*)?;`).FindStringSubmatch(ready)
	if apiPass == nil || readyPass == nil {
		t.Fatalf("cannot find proxy_pass in the API location (%v) or readiness location (%v)", apiPass, readyPass)
	}
	if apiPass[1] != readyPass[1] {
		t.Errorf("readiness proxies to %s, the API location to %s: both must target the server Service", readyPass[1], apiPass[1])
	}
	if !strings.Contains(ready, "proxy_connect_timeout") || !strings.Contains(ready, "proxy_read_timeout") {
		t.Errorf("readiness location needs short proxy timeouts so a hung backend fails the probe:\n%s", ready)
	}
	// Security headers apply here too (nginx add_header does not inherit into a
	// location that defines its own), and the backend's copy is hidden.
	for _, loc := range []struct{ name, body string }{{liveness, live}, {readiness, ready}} {
		if !strings.Contains(loc.body, "add_header X-Frame-Options") {
			t.Errorf("location %s lost the baseline security headers", loc.name)
		}
	}
	if !strings.Contains(ready, "proxy_hide_header X-Frame-Options") {
		t.Errorf("readiness location %s must hide the backend's security headers like the API location", readiness)
	}
}
