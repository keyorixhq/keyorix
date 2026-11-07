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
// (a dead backend must not restart nginx); readiness must reflect the backend so
// the pod goes NotReady (not restarted) when the backend is down.
//
// HELM-WEB-HEALTH-1 (#3910): the readiness location is also what the public
// ingress reaches, so it must answer STATUS ONLY. The backend /health is asked
// through an internal auth_request location and its body never leaves nginx.
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

// nginxLocationBlock returns the body of the first `location <head> {`
// (brace-balanced) from the rendered nginx.conf. head is a regexp for what sits
// between `location` and the opening brace.
func nginxLocationBlock(conf, head string) (string, bool) {
	re := regexp.MustCompile(`(?m)^\s*location\s+` + head + `\s*\{`)
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

// nginxExactLocation returns the body of `location = <path> {`.
func nginxExactLocation(conf, path string) (string, bool) {
	return nginxLocationBlock(conf, `=\s*`+regexp.QuoteMeta(path))
}

// nginxNamedLocation returns the body of `location @<name> {`.
func nginxNamedLocation(conf, name string) (string, bool) {
	return nginxLocationBlock(conf, "@"+regexp.QuoteMeta(name))
}

func TestHelmWebProbesLivenessStaticReadinessStatusOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"secureBaseline-on", []string{"--set", "secureBaseline.enabled=true"}},
		{"secureBaseline-off", []string{"--set", "secureBaseline.enabled=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readiness, liveness := webProbePaths(t, helmRenderWeb(t, "web-deployment.yaml", tc.extra...))
			conf := helmRenderWeb(t, "web-config.yaml", tc.extra...)
			checkWebHealthLocations(t, conf, readiness, liveness)
		})
	}
}

func checkWebHealthLocations(t *testing.T, conf, readiness, liveness string) {
	t.Helper()

	// (a) the two probes must differ and both name an existing location.
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
	case strings.Contains(live, "proxy_pass") || strings.Contains(live, "auth_request"):
		t.Errorf("liveness location %s reaches a backend: a backend outage would restart the web pod:\n%s", liveness, live)
	case !strings.Contains(live, "return 200"):
		t.Errorf("liveness location %s must be a static `return 200`:\n%s", liveness, live)
	}

	// (c) the readiness path exists, never proxies itself, and asks the backend
	// through an auth_request to an internal location.
	ready, ok := nginxExactLocation(conf, readiness)
	if !ok {
		t.Fatalf("readiness path %q has no `location = %s` block in the rendered nginx.conf", readiness, readiness)
	}
	if strings.Contains(ready, "proxy_pass") {
		t.Errorf("readiness location %s proxies the backend response to the (public) caller; it must answer status only:\n%s", readiness, ready)
	}
	if strings.Contains(ready, "return ") {
		t.Errorf("readiness location %s answers with `return` in the rewrite phase, which runs before auth_request and would always say 200:\n%s", readiness, ready)
	}
	authRe := regexp.MustCompile(`auth_request\s+(/\S+?);`).FindStringSubmatch(ready)
	if authRe == nil {
		t.Fatalf("readiness location %s must use auth_request to consult the backend:\n%s", readiness, ready)
	}
	probe, ok := nginxExactLocation(conf, authRe[1])
	if !ok {
		t.Fatalf("auth_request target %q has no `location = %s` block", authRe[1], authRe[1])
	}
	if !regexp.MustCompile(`(?m)^\s*internal;`).MatchString(probe) {
		t.Errorf("auth_request target %s must be `internal;` so it is not reachable from outside:\n%s", authRe[1], probe)
	}
	if strings.Contains(probe, "return ") {
		t.Errorf("auth_request target %s must reach the backend, not answer statically:\n%s", authRe[1], probe)
	}
	if !strings.Contains(probe, "proxy_pass_request_body off") {
		t.Errorf("auth_request target %s must not forward a request body", authRe[1])
	}

	// (d) the probe location targets the same upstream as the /api proxy, with
	// TLS verification matching it, and short timeouts.
	apiPass := regexp.MustCompile(`proxy_pass\s+(https?://[^\s;/]+)`).FindStringSubmatch(conf)
	probePass := regexp.MustCompile(`proxy_pass\s+(https?://[^\s;/]+)/health;`).FindStringSubmatch(probe)
	if apiPass == nil || probePass == nil {
		t.Fatalf("cannot find proxy_pass in the API location (%v) or the backend probe location (%v):\n%s", apiPass, probePass, probe)
	}
	if apiPass[1] != probePass[1] {
		t.Errorf("backend probe proxies to %s, the API location to %s: both must target the server Service", probePass[1], apiPass[1])
	}
	if strings.HasPrefix(probePass[1], "https://") != strings.Contains(probe, "proxy_ssl_verify on") {
		t.Errorf("backend probe TLS verification does not match its scheme %s:\n%s", probePass[1], probe)
	}
	if !strings.Contains(probe, "proxy_connect_timeout") || !strings.Contains(probe, "proxy_read_timeout") {
		t.Errorf("backend probe needs short proxy timeouts so a hung backend fails the probe:\n%s", probe)
	}

	// The probe is a proxied request like the API location: it must overwrite the
	// forwarding headers, otherwise a client-supplied X-Real-IP / X-Forwarded-For
	// reaches a server that trusts this pod as a proxy and lands in its request log.
	for _, h := range []string{
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
	} {
		if !strings.Contains(probe, h) {
			t.Errorf("backend probe must set `%s` like the API location (trusted-proxy contract):\n%s", h, probe)
		}
	}

	// (e) failure maps to a fixed 503, success to a fixed 200, both through named
	// locations that exist, and neither carries backend data.
	errRe := regexp.MustCompile(`error_page\s+([0-9 ]+?)\s*=\s*@(\S+?);`).FindStringSubmatch(ready)
	upRe := regexp.MustCompile(`try_files\s+\S+\s+@(\S+?);`).FindStringSubmatch(ready)
	if errRe == nil || upRe == nil {
		t.Fatalf("readiness location %s needs error_page ... = @down and try_files ... @up:\n%s", readiness, ready)
	}
	for _, code := range []string{"500", "502", "503", "504"} {
		if !strings.Contains(" "+errRe[1]+" ", " "+code+" ") {
			t.Errorf("readiness error_page does not map %s to the fixed 503: %q", code, errRe[1])
		}
	}
	down, ok := nginxNamedLocation(conf, errRe[2])
	if !ok || !strings.Contains(down, "return 503") {
		t.Errorf("error_page target @%s must exist and `return 503`:\n%s", errRe[2], down)
	}
	up, ok := nginxNamedLocation(conf, upRe[1])
	if !ok || !strings.Contains(up, "return 200") {
		t.Errorf("try_files target @%s must exist and `return 200`:\n%s", upRe[1], up)
	}
	for _, loc := range []struct{ name, body string }{{liveness, live}, {"@" + errRe[2], down}, {"@" + upRe[1], up}} {
		if strings.Contains(loc.body, "proxy_pass") {
			t.Errorf("location %s proxies the backend", loc.name)
		}
		if !strings.Contains(loc.body, "add_header X-Frame-Options") {
			t.Errorf("location %s lost the baseline security headers", loc.name)
		}
	}

	// (f) the family check: no proxy_pass to a /health URL anywhere except the
	// internal auth_request target, so a backend health body can never be served.
	if got := len(regexp.MustCompile(`proxy_pass\s+\S*/health;`).FindAllString(conf, -1)); got != 1 {
		t.Errorf("expected exactly one proxy_pass to the backend /health (the internal probe), found %d", got)
	}
}
