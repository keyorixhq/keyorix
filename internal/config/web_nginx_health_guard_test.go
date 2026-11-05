package config

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3460: web/nginx.conf used to answer /health with a static 200, so the compose
// healthcheck and any load balancer reported "healthy" while the backend was
// down. /health must reflect the backend; the static answer lives at
// /nginx-health, which only the image-level HEALTHCHECK may use. /health answers
// status only (200 / 503): proxying the backend's body would expose backend
// health detail through the web container (HELM-WEB-HEALTH-1 does the same for
// the Helm web probe).
//
// This is a text guard over the config (nginx -t is not available in CI's Go
// jobs). It does not run nginx; the real-container check is the e2e VM's.

// nginxLocationBody returns the body of the first `location <header> {` block
// whose header matches exactly (whitespace-normalised), or false. It tracks brace
// depth after stripping # comments and quoted strings, like
// server/middleware.addHeaderInLocation.
func nginxLocationBody(conf, header string) (string, bool) {
	quoted := regexp.MustCompile(`"[^"]*"|'[^']*'`)
	var lines []string
	for raw := range strings.SplitSeq(conf, "\n") {
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = raw[:i]
		}
		lines = append(lines, quoted.ReplaceAllString(raw, `""`))
	}
	want := "location " + header
	depth, start := 0, -1
	var body []string
	for _, line := range lines {
		trimmed := strings.Join(strings.Fields(line), " ")
		if start < 0 {
			if !strings.HasPrefix(trimmed, want+" {") {
				continue
			}
			// Opening line; its tail may hold the whole one-line block.
			start = 1
			trimmed = strings.TrimSpace(trimmed[len(want)+2:])
			line = trimmed
			depth = 1
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			body = append(body, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(trimmed), "}")))
			return strings.Join(body, "\n"), true
		}
		body = append(body, trimmed)
	}
	return "", false
}

func checkWebNginxHealth(conf string) []string {
	var problems []string
	// /health answers STATUS ONLY: it must never proxy the backend's body to the
	// client, so it has no proxy_pass of its own. It asks the backend through an
	// auth_request subrequest (whose body nginx discards) and maps every failure
	// to a static 503.
	health, ok := nginxLocationBody(conf, "= /health")
	switch {
	case !ok:
		problems = append(problems, "no `location = /health` block")
	case strings.Contains(health, "proxy_pass"):
		problems = append(problems, "`location = /health` must not proxy_pass: that sends the backend's health body to the client (status only)")
	case !strings.Contains(health, "auth_request /_backend_health;"):
		problems = append(problems, "`location = /health` must `auth_request /_backend_health;`")
	case strings.Contains(health, "return "):
		problems = append(problems, "`location = /health` must not `return` (rewrite phase runs before auth_request and would hide a dead backend)")
	case !strings.Contains(health, "= @health_unavailable;"):
		problems = append(problems, "`location = /health` must map a failed subrequest to `@health_unavailable` with `error_page ... = @health_unavailable;`")
	case !strings.Contains(health, "@health_ok"):
		problems = append(problems, "`location = /health` must reach `@health_ok` with try_files")
	}
	for _, code := range []string{"401", "403", "500", "502", "503", "504"} {
		if ok && !regexp.MustCompile(`error_page[^;]*\b`+code+`\b[^;]*=`).MatchString(health) {
			problems = append(problems, "`location = /health` error_page must cover "+code)
		}
	}
	backend, ok := nginxLocationBody(conf, "= /_backend_health")
	switch {
	case !ok:
		problems = append(problems, "no `location = /_backend_health` block")
	case !strings.Contains(backend, "internal;"):
		problems = append(problems, "`location = /_backend_health` must be `internal;`")
	case !strings.Contains(backend, "proxy_pass $keyorix_backend/health;"):
		problems = append(problems, "`location = /_backend_health` must `proxy_pass $keyorix_backend/health;`")
	case !strings.Contains(backend, "include /etc/nginx/keyorix-backend.conf;"):
		problems = append(problems, "`location = /_backend_health` must include keyorix-backend.conf (sets $keyorix_backend and the TLS verification)")
	}
	if okBody, ok := nginxLocationBody(conf, "@health_ok"); !ok || !strings.Contains(okBody, "return 200") {
		problems = append(problems, "`location @health_ok` must `return 200`")
	}
	if down, ok := nginxLocationBody(conf, "@health_unavailable"); !ok || !strings.Contains(down, "return 503") {
		problems = append(problems, "`location @health_unavailable` must `return 503`")
	}
	static, ok := nginxLocationBody(conf, "= /nginx-health")
	switch {
	case !ok:
		problems = append(problems, "no `location = /nginx-health` block")
	case !strings.Contains(static, "return 200"):
		problems = append(problems, "`location = /nginx-health` must be a static `return 200`")
	case strings.Contains(static, "proxy_pass") || strings.Contains(static, "auth_request"):
		problems = append(problems, "`location = /nginx-health` must not proxy: it reports the web container only")
	}
	return problems
}

func TestWebNginxHealthIsBackendAwareStatusOnly(t *testing.T) {
	data, err := os.ReadFile("../../web/nginx.conf") // #nosec G304 -- fixed relative path to a repo file
	require.NoError(t, err)
	assert.Empty(t, checkWebNginxHealth(string(data)))
}

// The image HEALTHCHECK probes the container itself (static); the compose web
// healthcheck probes the backend-aware /health. Both must stay as they are or the
// two halves of #3460 drift apart.
func TestWebHealthchecksReferenceTheRightEndpoints(t *testing.T) {
	dockerfile, err := os.ReadFile("../../web/Dockerfile") // #nosec G304 -- fixed relative path
	require.NoError(t, err)
	assert.Contains(t, string(dockerfile), "http://127.0.0.1/nginx-health",
		"web/Dockerfile HEALTHCHECK must use the static /nginx-health: /health depends on the backend")

	compose, err := os.ReadFile("../../docker-compose.yml") // #nosec G304 -- fixed relative path
	require.NoError(t, err)
	assert.Contains(t, string(compose), `"http://127.0.0.1/health"`,
		"docker-compose.yml web healthcheck must use /health so it reflects the backend")
}

func TestCheckWebNginxHealth_DetectsRegressions(t *testing.T) {
	good := `server {
    location = /nginx-health { return 200 "healthy\n"; }
    location = /health {
        auth_request /_backend_health;
        error_page 401 403 500 502 503 504 = @health_unavailable;
        try_files /.none @health_ok;
    }
    location @health_ok { return 200 "healthy\n"; }
    location @health_unavailable { return 503 "unavailable\n"; }
    location = /_backend_health {
        internal;
        include /etc/nginx/keyorix-backend.conf;
        proxy_pass $keyorix_backend/health;
    }
}`
	assert.Empty(t, checkWebNginxHealth(good))

	// The pre-#3460 shape: static /health, no /nginx-health.
	static := `server {
    location /health {
        return 200 "healthy\n";
    }
}`
	assert.NotEmpty(t, checkWebNginxHealth(static))

	// The shape this guard used to require: /health proxies the backend body.
	proxied := strings.Replace(good, "auth_request /_backend_health;", "proxy_pass $keyorix_backend/health;", 1)
	assert.NotEmpty(t, checkWebNginxHealth(proxied))

	// /health static under the new name pair: a `return` would run before auth_request.
	staticHealth := strings.Replace(good, "try_files /.none @health_ok;", `return 200 "healthy\n";`, 1)
	assert.NotEmpty(t, checkWebNginxHealth(staticHealth))

	// A failed subrequest that is not mapped to 503 (the backend's 5xx would reach the client).
	noMap := strings.Replace(good, "error_page 401 403 500 502 503 504 = @health_unavailable;", "", 1)
	assert.NotEmpty(t, checkWebNginxHealth(noMap))

	// One status missing from error_page.
	missing := strings.Replace(good, "502 ", "", 1)
	assert.NotEmpty(t, checkWebNginxHealth(missing))

	// The subrequest target must not be reachable by clients.
	external := strings.Replace(good, "        internal;\n", "", 1)
	assert.NotEmpty(t, checkWebNginxHealth(external))

	// /nginx-health proxied to the backend.
	proxiedStatic := strings.Replace(good, `location = /nginx-health { return 200 "healthy\n"; }`,
		"location = /nginx-health { proxy_pass $keyorix_backend/health; }", 1)
	assert.NotEmpty(t, checkWebNginxHealth(proxiedStatic))
}
