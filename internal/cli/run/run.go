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
	runEnv         string
	runProject     string
	runToken       string
	runCleanEnv    bool
	runVarMappings []string
	runDeriveNames bool
)

// RunCmd is the top-level 'run' command.
var RunCmd = &cobra.Command{
	Use:   "run",
	Short: "Inject secrets as env vars and run a command",
	Long: `Fetch secrets for a project + environment, expose them as environment
variables, then execute the supplied command.

'keyorix run' does not inject anything by default — pick exactly one:

  --var NAME=secret-ref   (recommended) YOU choose the env var name.
    keyorix run --env production --var DATABASE_URL=db-password -- node app.js
    keyorix run --env production --var API_KEY=stripe-key --var DB=db-password -- ./myapp
    Repeatable. Only the named secrets are injected, under the names you gave
    them — a secret's own NAME never determines what env var it lands under.

  --derive-names   (deprecated) restore the old behavior: every secret in the
    project + environment is injected, with the env var key AUTO-DERIVED from
    the secret's own name (uppercase, non-alphanumeric → '_' — e.g. db-password
    becomes DB_PASSWORD). Deprecated because whoever can NAME a secret then
    controls which env var it becomes — including reserved ones like
    LD_PRELOAD or DYLD_INSERT_LIBRARIES — not just its value. Kept for
    backward compatibility; --var has no such gap because YOU supply the name.
    See https://github.com/keyorixhq/keyorix/issues/1816 for why this changed.

Project is resolved via: --project flag → KEYORIX_PROJECT env → active project
(set with 'keyorix project use') → "default" fallback.

Under --derive-names, if two different secret names collide onto the same env
var key after derivation (e.g. "my-secret" and "my_secret" both becoming
MY_SECRET), the command aborts with an error instead of silently letting one
overwrite the other — rename one of the secrets to resolve the collision.
Under --var, assigning the same NAME to two different secret-refs is the same
kind of error; assigning it twice to the SAME secret-ref is fine.

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
    unrelated CI secret, etc.).
  • --clean-env isolates the child from the INVOKING SHELL's leftover
    variables only. It does not isolate the secret from other observers: for
    the lifetime of the child process, any process able to read this OS
    user's process environment (e.g. another local process, or an operator
    with shell access to the host) can read the injected values — the same
    limitation every environment-variable-based secret injector shares, not
    something Keyorix can close.

Collision with the inherited environment:
  • --var: your explicit choice always wins. You named it, so overriding an
    inherited value IS the intent.
  • --derive-names: the INHERITED value wins instead — an auto-derived secret
    name never overrides something already set in the environment (a second,
    independent guard alongside the reserved-name filter: the filter stops a
    brand-new dangerous name like DYLD_INSERT_LIBRARIES from being introduced;
    this stops an already-set name from being silently overridden). If you
    need a derived secret to take precedence, use --var instead.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runRun,
}

func init() {
	RunCmd.Flags().StringVar(&runEnv, "env", "development", "Environment name (e.g. production)")
	RunCmd.Flags().StringVar(&runProject, "project", "", "Project name (overrides KEYORIX_PROJECT and active project)")
	RunCmd.Flags().StringVar(&runToken, "token", "", "Service or session token (overrides KEYORIX_TOKEN env var)")
	RunCmd.Flags().BoolVar(&runCleanEnv, "clean-env", false, "Start the child process with ONLY the injected secrets (plus a minimal PATH/HOME baseline) instead of the full inherited parent environment")
	RunCmd.Flags().StringArrayVar(&runVarMappings, "var", nil, "Inject one secret under an explicit env var name: --var NAME=secret-ref (repeatable, recommended)")
	RunCmd.Flags().BoolVar(&runDeriveNames, "derive-names", false, "Deprecated: inject every secret in the project+environment, deriving the env var name from the secret's own name")
}

func runRun(cmd *cobra.Command, args []string) error {
	// #1816: provenance fix. There is no implicit default anymore -- pick one
	// explicitly, loudly, rather than either silently doing nothing or silently
	// keeping the old (attacker-nameable) behavior. See the Long help text above
	// for the full reasoning.
	if len(runVarMappings) == 0 && !runDeriveNames {
		return errors.New(`'keyorix run' no longer injects secrets by default. Choose explicitly:
  --var NAME=secret-ref   (recommended) inject one secret, YOU name the env var
  --derive-names          (deprecated) restore the old auto-derived behavior
See https://github.com/keyorixhq/keyorix/issues/1816 for why.`)
	}

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
		secretsByName map[string]string
		fetchErr      error
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
		secretsByName, fetchErr = fetchSecretsRemote(ctx, endpoint, tok, projectName, runEnv)
	} else {
		secretsByName, fetchErr = fetchSecretsEmbedded(ctx, projectName, runEnv)
	}
	if fetchErr != nil {
		return fetchErr
	}

	derived, varMapped, err := resolveChildEnvVars(secretsByName, runVarMappings, runDeriveNames, projectName, runEnv)
	if err != nil {
		return err
	}

	return execChild(args, derived, varMapped, runCleanEnv)
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

	// List EVERY secret in the project + environment, keyed by its own raw NAME —
	// page through all of them so a project with more than one page doesn't leave
	// silently-missing secrets for --var to reference or --derive-names to inject.
	// Env-var-key derivation (toEnvKey/setEnvKey) happens later, in
	// resolveChildEnvVars, only for the --derive-names path; --var looks secrets
	// up by this same raw name directly, with no derivation involved.
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
			result[s.Name] = string(val)
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
			result[s.Name] = secretBody.Value
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

// dangerousEnvPrefixes and dangerousEnvExact together replace what used to be a
// single exact-name map (dangerousEnvVarNames). That map was itself the #G39 fix
// for toEnvKey deriving child env keys straight from an untrusted secret NAME with
// no filtering at all — but an exact-name list in a code-execution path is the
// same defect shape one layer down: it fails open on every name it doesn't happen
// to enumerate. Verification against a real dylib-injection PoC (2026-09-09,
// CLI-RUN-001 release-gate re-check) confirmed this: DYLD_INSERT_LIBRARIES —
// macOS's LD_PRELOAD equivalent, named in the ORIGINAL finding's own exploit
// scenario — was never in the list, and a secret literally named
// "dyld_insert_libraries" reached the child process and ran an attacker
// constructor. The fix is not "add DYLD_INSERT_LIBRARIES" (that just reproduces
// the same gap for the next sibling — LD_LIBRARY_PATH, GCONV_PATH, ... — one CVE
// at a time); it's covering the FAMILY each dangerous name belongs to.
//
// dangerousEnvPrefixes: any env key starting with one of these is dropped.
//   - LD_      the ELF/Mach-O dynamic linker's whole tunable surface (LD_PRELOAD,
//     LD_LIBRARY_PATH, LD_AUDIT, ...) — linker behavior, not app config.
//   - DYLD_    macOS dyld's equivalent of LD_ (DYLD_INSERT_LIBRARIES,
//     DYLD_LIBRARY_PATH, ...) — the exact family the live PoC used.
//   - NODE_    Node.js process-wide behavior flags (NODE_OPTIONS, NODE_PATH, ...).
//     Deliberate tradeoff: this also blocks the legitimate NODE_ENV: a
//     project secret writer controlling arbitrary NODE_OPTIONS content
//     outweighs a launched Node app not getting NODE_ENV from a secret
//     (operators can still set NODE_ENV as an ordinary shell/CI env var —
//     `keyorix run` inherits the parent environment unchanged; only
//     secret-derived keys are filtered here).
//   - PYTHON   CPython interpreter startup/path control (PYTHONPATH,
//     PYTHONSTARTUP, PYTHONHOME, ...). No trailing '_': some real names
//     (PYTHONDONTWRITEBYTECODE) don't have one after PYTHON.
//   - PERL5    Perl 5's interpreter option/library-path family (PERL5OPT,
//     PERL5LIB). No trailing '_', matching Perl's own naming.
//   - BASH_    bash's own startup-file control (BASH_ENV and siblings).
//   - GCONV_   glibc's character-conversion module loader (GCONV_PATH) — a
//     second, less-known arbitrary-code-loading primitive alongside
//     LD_PRELOAD.
//   - MALLOC_  glibc/macOS malloc tunables (MALLOC_CHECK_, MALLOC_CONF, ...),
//     usable for heap-exploitation primitives.
var dangerousEnvPrefixes = []string{
	"LD_", "DYLD_", "NODE_", "PYTHON", "PERL5", "BASH_", "GCONV_", "MALLOC_",
}

// dangerousEnvExact names variables that control shell/process behavior directly
// but don't belong to any linker/interpreter prefix family above:
//   - IFS    shell field-splitting; corrupting it can turn plain arguments into
//     separate words/code.
//   - ENV    sh's (non-bash) startup-file equivalent of BASH_ENV.
//   - HOME   many tools (git, ssh, npm, ...) resolve config/credentials relative
//     to HOME; redirecting it can hijack that resolution.
//   - SHELL  some tools shell out via `$SHELL -c ...` rather than a fixed
//     interpreter.
//   - PATH   executable resolution order for the whole child process tree.
//
// RUBYOPT and GIT_SSH_COMMAND (in the old exact list) are still covered: neither
// has siblings that would justify a prefix family of their own, so they stay
// exact entries rather than being dropped.
var dangerousEnvExact = map[string]bool{
	"IFS": true, "ENV": true, "HOME": true, "SHELL": true, "PATH": true,
	"RUBYOPT": true, "GIT_SSH_COMMAND": true,
}

// isDangerousEnvKey reports whether key is a reserved dynamic-linker/
// interpreter/shell control variable — see dangerousEnvPrefixes and
// dangerousEnvExact above for the two ways a key can match.
func isDangerousEnvKey(key string) bool {
	if dangerousEnvExact[key] {
		return true
	}
	for _, prefix := range dangerousEnvPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// dropDangerousEnvKeys removes any entry keyed on a dynamic-linker/interpreter/
// shell control variable name (isDangerousEnvKey) — envVars is already keyed by
// the DERIVED env var key (toEnvKey(secret.Name)), not the raw secret name; see
// fetchSecretsEmbedded/fetchSecretsRemote. Warns on stderr for each one dropped so
// the operator can see why a secret they expected didn't reach the child process
// (rather than either silently letting it override PATH/LD_PRELOAD/etc., or
// aborting the whole run over one secret name).
func dropDangerousEnvKeys(envVars map[string]string) map[string]string {
	out := make(map[string]string, len(envVars))
	for key, value := range envVars {
		if isDangerousEnvKey(key) {
			fmt.Fprintf(os.Stderr, "⚠️  a secret maps to the reserved environment variable %q — refusing to inject it (would override %s in the launched process)\n", key, key)
			continue
		}
		out[key] = value
	}
	return out
}

// isValidEnvVarName reports whether name is a syntactically valid POSIX
// environment variable name ([A-Za-z_][A-Za-z0-9_]*) — required for --var's
// operator-supplied NAME, since unlike a derived key (always produced by
// toEnvKey, which can only emit this shape) an operator can type anything.
func isValidEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// resolveChildEnvVars implements #1816's two independent levers:
//
//   - Provenance: --var (varMappings) lets the OPERATOR choose each env var
//     name explicitly, looking up each named secret directly in
//     secretsByName. --derive-names (deriveNames) keeps the old behavior —
//     inject every secret, deriving the env var name from the secret's own
//     name via toEnvKey/setEnvKey — behind an explicit, deprecated opt-in.
//   - Precedence: the two paths return SEPARATELY (derived, varMapped) rather
//     than a single merged map, because they get different treatment against
//     the INHERITED environment in buildChildEnv: derived entries no longer
//     override an inherited value (a second, independent guard alongside the
//     reserved-name filter below); varMapped entries still do, because an
//     explicit operator-chosen name IS the intent to override.
//
// The reserved-name filter (dropDangerousEnvKeys) applies ONLY to the derived
// path — an attacker only controls a name there. --var's NAME came from the
// operator, not from a secret's name, so no filter applies; isDangerousEnvKey
// is instead used to print a non-blocking heads-up, since typing --var
// LD_PRELOAD=... is far more likely to be deliberate than accidental and the
// operator's own intent should not be silently overridden by this command.
func resolveChildEnvVars(secretsByName map[string]string, varMappings []string, deriveNames bool, project, env string) (derived, varMapped map[string]string, err error) {
	if deriveNames {
		fmt.Fprintln(os.Stderr, "⚠️  --derive-names is deprecated: the env var name comes from each secret's own NAME, so whoever can name a project secret chooses (and can collide with) the env var it becomes. Prefer --var NAME=secret-ref, where you choose the name. See https://github.com/keyorixhq/keyorix/issues/1816.")
		d := make(map[string]string, len(secretsByName))
		envKeySources := make(map[string]string, len(secretsByName))
		for name, value := range secretsByName {
			if err := setEnvKey(d, envKeySources, name, value); err != nil {
				return nil, nil, err
			}
		}
		derived = dropDangerousEnvKeys(d)
	}

	if len(varMappings) > 0 {
		vm := make(map[string]string, len(varMappings))
		varSources := make(map[string]string, len(varMappings)) // envName -> secretRef
		for _, mapping := range varMappings {
			envName, secretRef, ok := strings.Cut(mapping, "=")
			if !ok || envName == "" || secretRef == "" {
				return nil, nil, fmt.Errorf("invalid --var %q: expected NAME=secret-ref", mapping)
			}
			if !isValidEnvVarName(envName) {
				return nil, nil, fmt.Errorf("invalid --var %q: %q is not a valid environment variable name", mapping, envName)
			}
			if existingRef, ok := varSources[envName]; ok && existingRef != secretRef {
				return nil, nil, fmt.Errorf("--var %s is assigned to two different secrets (%q and %q) — 'keyorix run' refuses to continue since one mapping would silently be dropped; use --var only once per name", envName, existingRef, secretRef)
			}
			value, ok := secretsByName[secretRef]
			if !ok {
				return nil, nil, fmt.Errorf("--var %s=%s: secret %q not found in project %q / environment %q", envName, secretRef, secretRef, project, env)
			}
			if isDangerousEnvKey(envName) {
				fmt.Fprintf(os.Stderr, "⚠️  --var maps secret %q onto %q, a reserved environment variable — proceeding because you asked for it explicitly; double-check this is intentional\n", secretRef, envName)
			}
			varSources[envName] = secretRef
			vm[envName] = value
		}
		varMapped = vm
	}

	return derived, varMapped, nil
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
func execChild(args []string, derived, varMapped map[string]string, cleanEnv bool) error {
	childEnv := buildChildEnv(derived, varMapped, cleanEnv)

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
// environment.
//
// #1816: the two injected-secret sources get different collision precedence against
// that base, matching the reasoning in resolveChildEnvVars's doc comment:
//   - derived (--derive-names, attacker-nameable): does NOT override an inherited
//     value — a name already present wins. This is independent of, not a substitute
//     for, dropDangerousEnvKeys's filter: the filter stops a brand-new dangerous
//     name (e.g. DYLD_INSERT_LIBRARIES, not normally set) from being introduced at
//     all; this stops an already-set name from being silently overridden, including
//     one the filter doesn't yet enumerate. Neither closes the whole class alone.
//   - varMapped (--var, operator-chosen): DOES override an inherited value — the
//     operator named it explicitly, so overriding is the intent, not an accident.
func buildChildEnv(derived, varMapped map[string]string, cleanEnv bool) []string {
	// A single map, not incremental slice appends: exec.Cmd.Env technically defines
	// "last duplicate key wins" for a slice with repeats, but relying on that
	// implicitly here would make the derived-path's explicit skip-on-collision
	// (below) and the varMapped-path's override-on-collision inconsistent in HOW
	// each achieves its precedence — one by never adding a second entry, the other
	// by silently trusting slice order. A map makes both paths equally explicit and
	// guarantees the final []string has no duplicate keys at all.
	env := make(map[string]string)
	if cleanEnv {
		for _, k := range []string{"PATH", "HOME"} {
			if v, ok := os.LookupEnv(k); ok {
				env[k] = v // NOSONAR -- intentional minimal PATH/HOME baseline for clean-env subprocess
			}
		}
	} else {
		for _, kv := range filterSensitiveEnv(os.Environ()) {
			k, v, _ := strings.Cut(kv, "=")
			env[k] = v
		}
	}

	for k, v := range derived {
		if _, alreadyInherited := env[k]; alreadyInherited {
			fmt.Fprintf(os.Stderr, "⚠️  a --derive-names secret maps to %q, which is already set in the inherited environment — keeping the inherited value (derived names no longer override on collision; use --var if this secret should take precedence)\n", k)
			continue
		}
		env[k] = v
	}
	for k, v := range varMapped {
		env[k] = v // explicit operator intent always wins, replacing any inherited or derived value
	}

	childEnv := make([]string, 0, len(env))
	for k, v := range env {
		childEnv = append(childEnv, k+"="+v)
	}
	return childEnv
}
