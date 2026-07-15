package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	runEnv      string
	runProject  string
	runToken    string
	runCleanEnv bool
)

// RunCmd is the top-level 'run' command.
var RunCmd = &cobra.Command{
	Use:   "run",
	Short: "Inject secrets as env vars and run a command",
	Long: `Fetch secrets for a project + environment, expose them as environment
variables, then execute the supplied command.

  keyorix run --env production -- node app.js
  keyorix run --env development -- flask run
  keyorix run --env staging -- npm start

Project is resolved via: --project flag → KEYORIX_PROJECT env → active project
(set with 'keyorix project use') → "default" fallback.

Each secret name is uppercased and non-alphanumeric characters are
replaced with underscores before becoming an env var key:

  db-password  →  DB_PASSWORD
  api.endpoint →  API_ENDPOINT

Authentication:
  • Session tokens written by 'keyorix auth login' are used automatically
    when the CLI is in client mode.
  • For service accounts / CI/CD, set KEYORIX_TOKEN (or --token) and
    point the CLI at a server with 'keyorix connect' or KEYORIX_SERVER.

Environment isolation:
  • By default the child process inherits the FULL parent environment plus
    the injected secrets, matching how most shells/tools behave.
  • Pass --clean-env to start the child from ONLY the injected secrets
    (plus a minimal PATH/HOME baseline) instead — use this when you don't
    want the child to also see whatever else is already exported in the
    invoking shell (a leftover token from a prior 'keyorix run', an
    unrelated CI secret, etc.).`,
	Args: cobra.MinimumNArgs(1),
	RunE: runRun,
}

func init() {
	RunCmd.Flags().StringVar(&runEnv, "env", "development", "Environment name (e.g. production)")
	RunCmd.Flags().StringVar(&runProject, "project", "", "Project name (overrides KEYORIX_PROJECT and active project)")
	RunCmd.Flags().StringVar(&runToken, "token", "", "Service or session token (overrides KEYORIX_TOKEN env var)")
	RunCmd.Flags().BoolVar(&runCleanEnv, "clean-env", false, "Start the child process with ONLY the injected secrets (plus a minimal PATH/HOME baseline) instead of the full inherited parent environment")
}

func runRun(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Resolve project via ADR-016 chain: --project → KEYORIX_PROJECT → cli.yaml → "default"
	projectName, err := common.ResolveProject(runProject)
	if err != nil {
		// Graceful fallback for CI/CD scripts that pre-date project context
		projectName = "default"
	}

	var (
		envVars  map[string]string
		fetchErr error
	)

	// --token flag overrides the token resolved by ResolveRemote. Passing it literally is
	// insecure (visible via ps/proc and saved in shell history) — prefer KEYORIX_TOKEN.
	endpoint, tok, remoteOK := common.ResolveRemote()
	if runToken != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --token on the command line is insecure (visible via ps/proc and saved in shell history); prefer the KEYORIX_TOKEN environment variable.")
		tok = runToken
		remoteOK = endpoint != ""
	}

	if remoteOK {
		envVars, fetchErr = fetchSecretsRemote(ctx, endpoint, tok, projectName, runEnv)
	} else {
		envVars, fetchErr = fetchSecretsEmbedded(ctx, projectName, runEnv)
	}
	if fetchErr != nil {
		return fetchErr
	}

	return execChild(args, envVars, runCleanEnv)
}

// ── Embedded mode ─────────────────────────────────────────────────────────────

// fetchSecretsEmbedded uses the local core service (direct DB access).
func fetchSecretsEmbedded(ctx context.Context, project, env string) (map[string]string, error) { // NOSONAR -- cognitive complexity 21, suppress go:S3776
	svc, err := common.InitializeCoreService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service: %w", err)
	}

	// Resolve project → ID
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	var projectID uint
	for _, p := range projects {
		if strings.EqualFold(p.Name, project) {
			projectID = p.ID
			break
		}
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project %q not found", project)
	}

	// Resolve environment → ID
	environments, err := svc.ListEnvironments(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list environments: %w", err)
	}
	var envID uint
	for _, e := range environments {
		if strings.EqualFold(e.Name, env) {
			envID = e.ID
			break
		}
	}
	if envID == 0 {
		return nil, fmt.Errorf("environment %q not found", env)
	}

	// Inject EVERY secret in the project + environment — page through all of them
	// so a project with more than one page doesn't start the subprocess with
	// silently missing environment variables.
	const pageSize = 500
	result := make(map[string]string)
	for page := 1; ; page++ {
		secrets, _, err := svc.ListSecrets(ctx, &coreStorage.SecretFilter{
			ProjectID:     &projectID,
			EnvironmentID: &envID,
			Page:          page,
			PageSize:      pageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}
		for _, s := range secrets {
			val, err := svc.GetSecretValue(ctx, s.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping secret %q (id=%d): %v\n", s.Name, s.ID, err)
				continue
			}
			result[toEnvKey(s.Name)] = string(val)
		}
		if len(secrets) < pageSize {
			break
		}
	}
	return result, nil
}

// ── Remote / client mode ──────────────────────────────────────────────────────

// apiClient makes authenticated requests to the Keyorix HTTP API.
type apiClient struct {
	endpoint string
	token    string
	http     *http.Client
}

// get performs a GET, strips the {"data":…} wrapper, and unmarshals into out.
func (c *apiClient) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if envelope.Data == nil {
		return fmt.Errorf("empty data in response from %s", path)
	}
	return json.Unmarshal(envelope.Data, out)
}

// fetchSecretsRemote fetches secrets by talking to the Keyorix HTTP API.
func fetchSecretsRemote(ctx context.Context, endpoint, token, project, env string) (map[string]string, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	api := &apiClient{
		endpoint: endpoint,
		token:    token,
		http:     &http.Client{},
	}

	// ── 1. Resolve project name → ID ─────────────────────────────────────────
	var projBody struct {
		Projects []*models.Project `json:"projects"`
	}
	if err := api.get(ctx, "/api/v1/projects", &projBody); err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	var nsID uint
	for _, p := range projBody.Projects {
		if strings.EqualFold(p.Name, project) {
			nsID = p.ID
			break
		}
	}
	if nsID == 0 {
		return nil, fmt.Errorf("project %q not found on server", project)
	}

	// ── 2. Resolve environment name → ID ──────────────────────────────────────
	var envBody struct {
		Environments []*models.Environment `json:"environments"`
	}
	if err := api.get(ctx, "/api/v1/environments", &envBody); err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	var envID uint
	for _, e := range envBody.Environments {
		if strings.EqualFold(e.Name, env) {
			envID = e.ID
			break
		}
	}
	if envID == 0 {
		return nil, fmt.Errorf("environment %q not found on server", env)
	}

	// ── 3+4. Page through ALL secrets and fetch each value ─────────────────────
	// (a single capped page would inject only the first page's env vars).
	const pageSize = 500
	result := make(map[string]string)
	for page := 1; ; page++ {
		listPath := fmt.Sprintf(
			"/api/v1/secrets?project_id=%d&environment_id=%d&page_size=%d&page=%d",
			nsID, envID, pageSize, page,
		)
		var secretsBody struct {
			Secrets []struct {
				ID   uint   `json:"id"`
				Name string `json:"name"`
			} `json:"secrets"`
		}
		if err := api.get(ctx, listPath, &secretsBody); err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		for _, s := range secretsBody.Secrets {
			var secretBody struct {
				Value string `json:"value"`
			}
			path := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", s.ID)
			if err := api.get(ctx, path, &secretBody); err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping secret %q (id=%d): %v\n", s.Name, s.ID, err)
				continue
			}
			result[toEnvKey(s.Name)] = secretBody.Value
		}
		if len(secretsBody.Secrets) < pageSize {
			break
		}
	}
	return result, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// toEnvKey converts a secret name to a valid environment variable key.
func toEnvKey(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// sensitiveEnvSuffixes mark a KEYORIX_-prefixed env var as this CLI invocation's own
// credential (an auth token, password, API key, secret, or DB DSN) rather than
// something a launched command needs.
var sensitiveEnvSuffixes = []string{"_TOKEN", "_PASSWORD", "_SECRET", "_API_KEY", "_DSN", "_KEK"}

// filterSensitiveEnv drops Keyorix's own credential env vars (e.g. KEYORIX_TOKEN, the
// token this invocation used to authenticate) from the environment inherited by the
// child process. 'keyorix run' still inherits the rest of the parent environment
// unchanged (PATH, HOME, and any other var) — that inheritance is the point of `run`,
// matching how a plain subshell behaves — but the child (and anything it in turn
// spawns) has no legitimate need for the credentials THIS CLI invocation used to reach
// Keyorix, so those are withheld rather than handed down by default.
func filterSensitiveEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if isSensitiveKeyorixEnv(key) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// isSensitiveKeyorixEnv reports whether key is a Keyorix-internal credential variable
// (KEYORIX_ prefix plus a token/password/secret/key/DSN suffix).
func isSensitiveKeyorixEnv(key string) bool {
	if !strings.HasPrefix(key, "KEYORIX_") {
		return false
	}
	for _, suf := range sensitiveEnvSuffixes {
		if strings.HasSuffix(key, suf) {
			return true
		}
	}
	return false
}

// execChild builds the child environment and executes the command. By default (cleanEnv
// false) the child inherits the FULL parent environment (minus Keyorix's own credential
// vars — filterSensitiveEnv, #103) plus the injected secrets — the long-standing,
// backward-compatible behavior. With cleanEnv true (--clean-env), the child starts from
// ONLY the injected secrets plus a minimal PATH/HOME baseline so it can still locate
// binaries and its home directory; every other variable already present in the invoking
// shell (a leftover token from a prior `keyorix run`, an unrelated CI secret, etc.) is NOT
// inherited. This is opt-in hardening for #164 — broader than #103's Keyorix-specific
// filtering, for callers who don't want the child to see the invoking shell's environment
// at all.
func execChild(args []string, extraEnv map[string]string, cleanEnv bool) error {
	childEnv := buildChildEnv(extraEnv, cleanEnv)

	c := exec.Command(args[0], args[1:]...) // #nosec G204
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = childEnv

	if err := c.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

// buildChildEnv computes the environment slice passed to the child process. By default
// (cleanEnv false) it starts from the FULL parent environment minus Keyorix's own
// credential vars (filterSensitiveEnv, #103) — the long-standing, backward-compatible
// behavior. With cleanEnv true it starts from ONLY a minimal PATH/HOME baseline (so the
// child can still locate binaries and its home directory), NOT the rest of the parent
// environment. In both cases extraEnv (the injected secrets) is appended last.
func buildChildEnv(extraEnv map[string]string, cleanEnv bool) []string {
	var childEnv []string
	if cleanEnv {
		for _, k := range []string{"PATH", "HOME"} {
			if v, ok := os.LookupEnv(k); ok {
				childEnv = append(childEnv, k+"="+v)
			}
		}
	} else {
		childEnv = filterSensitiveEnv(os.Environ())
	}
	for k, v := range extraEnv {
		childEnv = append(childEnv, k+"="+v)
	}
	return childEnv
}
