package run

import (
	"context"
	"errors"
	"fmt"
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

If two different secret names collide onto the same env var key after this
conversion (e.g. "my-secret" and "my_secret" both becoming MY_SECRET), the
command aborts with an error instead of silently letting one overwrite the
other — rename one of the secrets to resolve the collision.

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
	// context.Background() with NO deadline attached: matches the other 100+
	// common.RemoteClient call sites across this CLI (secret/rbac/machine/rotation/
	// project/dynamic, etc — see NewRemoteClient's own comment). The hang protection
	// against a stalled/malicious KEYORIX_SERVER comes from common.RemoteClient's
	// per-request http.Client.Timeout (fetchSecretsRemote below), not a context
	// deadline: fetchSecretsRemote pages through and fetches every secret in the
	// project/environment (up to maxRunInjectedSecrets) as a sequence of individual
	// requests, so a single fixed *total* deadline here would risk aborting a
	// legitimately large — but healthy — fetch partway through. The child process
	// execChild launches afterwards is unaffected either way: it takes no context and
	// is free to run indefinitely, matching 'keyorix run's interactive/streaming design.
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

	envVars = dropDangerousEnvKeys(envVars)

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
	envKeySources := make(map[string]string)
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
			if err := setEnvKey(result, envKeySources, s.Name, string(val)); err != nil {
				return nil, err
			}
		}
		if len(secrets) < pageSize {
			break
		}
	}
	return result, nil
}

// ── Remote / client mode ──────────────────────────────────────────────────────

// fetchSecretsRemote fetches secrets by talking to the Keyorix HTTP API through
// common.RemoteClient (not a homegrown *http.Client) so this command gets the
// same request timeout and anti-SSRF redirect refusal as every other CLI
// remote-mode command (#G71) — this previously ran on a zero-value http.Client
// with an infinite Timeout. endpoint/token are passed explicitly (rather than
// letting the client re-resolve them) because the caller may have overridden
// the token from --token.
func fetchSecretsRemote(ctx context.Context, endpoint, token, project, env string) (map[string]string, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	rc, ok := common.NewRemoteClientWithCredentials(endpoint, token)
	if !ok {
		return nil, fmt.Errorf("invalid remote endpoint %q", endpoint)
	}

	// ── 1. Resolve project name → ID ─────────────────────────────────────────
	var projBody struct {
		Projects []*models.Project `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &projBody); err != nil {
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
	// Scoped to the just-resolved project (nsID), not the deployment-wide
	// listing: picking the first case-insensitive name match across every
	// project's environments could resolve --environment to a different
	// project's same-named environment than the one --project just resolved,
	// silently fetching/injecting the wrong project's secrets (G78 sibling —
	// see internal/cli/rbac/remote.go's resolveEnvironmentIDByName for the
	// original finding).
	var envBody struct {
		Environments []*models.Environment `json:"environments"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/projects/%d/environments", nsID), &envBody); err != nil {
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
	// maxRunInjectedSecrets bounds the total number of secrets injected as child-
	// process env vars (#G44): with no cap, a project holding a very large number of
	// secrets can exhaust CLI memory fetching them one by one, or overrun the OS's
	// environment-block size limit (ARG_MAX) when they're handed to the child
	// process, silently truncating or failing the launch instead of a clear error.
	const maxRunInjectedSecrets = 2000
	result := make(map[string]string)
	envKeySources := make(map[string]string)
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
		if err := rc.Get(ctx, listPath, &secretsBody); err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		if len(result)+len(secretsBody.Secrets) > maxRunInjectedSecrets {
			return nil, fmt.Errorf("project %q/environment %q has more than %d secrets — 'keyorix run' injects every secret as an env var and refuses to continue past this cap; narrow the environment or use a different injection method", project, env, maxRunInjectedSecrets)
		}
		for _, s := range secretsBody.Secrets {
			var secretBody struct {
				Value string `json:"value"`
			}
			path := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", s.ID)
			if err := rc.Get(ctx, path, &secretBody); err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping secret %q (id=%d): %v\n", s.Name, s.ID, err)
				continue
			}
			if err := setEnvKey(result, envKeySources, s.Name, secretBody.Value); err != nil {
				return nil, err
			}
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

// setEnvKey records secret name's value under its toEnvKey-derived key in result,
// tracking which secret name produced each key in envKeySources so a collision can
// be detected. Two DIFFERENT secret names can sanitize to the SAME env var key
// (e.g. "my-secret" and "my_secret" both become MY_SECRET) — without this check the
// second secret processed would silently overwrite the first in result, and the
// operator would have no indication that one of their two secrets never actually
// reached the child process's environment (which could read the WRONG secret's
// value under an expected variable name). Matches this codebase's fail-closed-on-
// ambiguity convention (see the dangerousEnvVarNames / maxRunInjectedSecrets guards
// above): abort the whole run rather than silently picking a winner.
func setEnvKey(result map[string]string, envKeySources map[string]string, name, value string) error {
	key := toEnvKey(name)
	if existing, ok := envKeySources[key]; ok && existing != name {
		return fmt.Errorf("secrets %q and %q both sanitize to the same environment variable %q — 'keyorix run' refuses to continue since one of them would silently be dropped from the child process's environment; rename one of the secrets to avoid the collision", existing, name, key)
	}
	envKeySources[key] = name
	result[key] = value
	return nil
}

// dangerousEnvVarNames names environment variables that affect dynamic-linker,
// interpreter, or shell behavior for the CHILD PROCESS `keyorix run` launches — not
// Keyorix's own credentials (see sensitiveEnvSuffixes below, a separate concern).
// #G39: toEnvKey derives the child's env var keys directly from a project secret's
// NAME (uppercased, non-alphanumeric → '_'), with no filtering at all — a secret
// named "path" or "ld_preload" becomes an env key that collides with (and, since
// buildChildEnv appends the injected secrets LAST, overrides) one of these,
// letting a project-level secret WRITER hijack or control code execution in
// whatever `keyorix run` launches, without ever needing direct system access
// themselves. Matches the detection_idea's own required-coverage list exactly.
var dangerousEnvVarNames = map[string]bool{
	"LD_PRELOAD":      true,
	"BASH_ENV":        true,
	"NODE_OPTIONS":    true,
	"PATH":            true,
	"PERL5OPT":        true,
	"RUBYOPT":         true,
	"GIT_SSH_COMMAND": true,
}

// dropDangerousEnvKeys removes any entry keyed on a dynamic-linker/interpreter/
// shell control variable name (dangerousEnvVarNames) — envVars is already keyed by
// the DERIVED env var key (toEnvKey(secret.Name)), not the raw secret name; see
// fetchSecretsEmbedded/fetchSecretsRemote. Warns on stderr for each one dropped so
// the operator can see why a secret they expected didn't reach the child process
// (rather than either silently letting it override PATH/LD_PRELOAD/etc., or
// aborting the whole run over one secret name).
func dropDangerousEnvKeys(envVars map[string]string) map[string]string {
	out := make(map[string]string, len(envVars))
	for key, value := range envVars {
		if dangerousEnvVarNames[key] {
			fmt.Fprintf(os.Stderr, "⚠️  a secret maps to the reserved environment variable %q — refusing to inject it (would override %s in the launched process)\n", key, key)
			continue
		}
		out[key] = value
	}
	return out
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
				childEnv = append(childEnv, k+"="+v) // NOSONAR -- intentional minimal PATH/HOME baseline for clean-env subprocess
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
