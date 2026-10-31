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
// down. /health must proxy to the backend; the static answer lives at
// /nginx-health, which only the image-level HEALTHCHECK may use.
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
	health, ok := nginxLocationBody(conf, "= /health")
	switch {
	case !ok:
		problems = append(problems, "no `location = /health` block")
	case !strings.Contains(health, "proxy_pass $keyorix_backend/health;"):
		problems = append(problems, "`location = /health` must `proxy_pass $keyorix_backend/health;`")
	case strings.Contains(health, "return "):
		problems = append(problems, "`location = /health` must not answer statically (`return`)")
	case !strings.Contains(health, "include /etc/nginx/keyorix-backend.conf;"):
		problems = append(problems, "`location = /health` must include keyorix-backend.conf (sets $keyorix_backend and the TLS verification)")
	}
	static, ok := nginxLocationBody(conf, "= /nginx-health")
	switch {
	case !ok:
		problems = append(problems, "no `location = /nginx-health` block")
	case !strings.Contains(static, "return 200"):
		problems = append(problems, "`location = /nginx-health` must be a static `return 200`")
	case strings.Contains(static, "proxy_pass"):
		problems = append(problems, "`location = /nginx-health` must not proxy: it reports the web container only")
	}
	return problems
}

func TestWebNginxHealthProxiesBackend(t *testing.T) {
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

	// /health static under the new name pair.
	staticHealth := strings.Replace(good, "proxy_pass $keyorix_backend/health;", `return 200 "healthy\n";`, 1)
	assert.NotEmpty(t, checkWebNginxHealth(staticHealth))

	// /nginx-health proxied to the backend.
	proxiedStatic := strings.Replace(good, `return 200 "healthy\n";`, "proxy_pass $keyorix_backend/health;", 1)
	assert.NotEmpty(t, checkWebNginxHealth(proxiedStatic))
}
