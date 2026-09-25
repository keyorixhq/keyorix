// run.go ports `keyorix run` (docs/cli-split-inventory.md §2.7, §8 Finding S18, FINISH-SPLIT
// step 2): fetch secrets and inject them as env vars for a child process, remote-only. The
// old CLI's embedded/local-mode fetch is deliberately NOT ported -- dropping it is a
// security fix, not just cleanup: it had zero authorization check (bare
// svc.GetSecretValue, never the permission-checked variant) and zero audit event, unlike
// the remote path in the same file, which correctly used the permission-checked,
// audited REST route. This module's REST-only design removes that whole gap by
// construction (ADR-108 Decision A).
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var (
	runEnv         string
	runProject     string
	runCleanEnv    bool
	runVarMappings []string
	runDeriveNames bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Inject secrets as env vars and run a command",
	Long: `Fetch secrets for a project + environment, expose them as environment
variables, then execute the supplied command.

'keyorix-next run' does not inject anything by default -- pick exactly one:

  --var NAME=secret-ref   (recommended) YOU choose the env var name.
    keyorix-next run --env production --var DATABASE_URL=db-password -- node app.js
    Repeatable. Only the named secrets are injected, under the names you gave
    them -- a secret's own NAME never determines what env var it lands under.

  --derive-names   (deprecated) inject every secret in the project + environment,
    with the env var key AUTO-DERIVED from the secret's own name. Deprecated
    because whoever can NAME a secret then controls which env var it becomes --
    including reserved ones like LD_PRELOAD -- not just its value. See
    https://github.com/keyorixhq/keyorix/issues/1816 for why this changed.

Project is resolved via: --project flag -> KEYORIX_PROJECT env.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runRun,
}

func init() {
	runCmd.Flags().StringVar(&runEnv, "env", "development", "Environment name (e.g. production)")
	runCmd.Flags().StringVar(&runProject, "project", "", "Project name (overrides KEYORIX_PROJECT)")
	runCmd.Flags().BoolVar(&runCleanEnv, "clean-env", false, "Start the child process with ONLY the injected secrets (plus a minimal PATH/HOME baseline) instead of the full inherited parent environment")
	runCmd.Flags().StringArrayVar(&runVarMappings, "var", nil, "Inject one secret under an explicit env var name: --var NAME=secret-ref (repeatable, recommended)")
	runCmd.Flags().BoolVar(&runDeriveNames, "derive-names", false, "Deprecated: inject every secret in the project+environment, deriving the env var name from the secret's own name")
	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	if len(runVarMappings) == 0 && !runDeriveNames {
		return errors.New(`'keyorix-next run' does not inject secrets by default. Choose explicitly:
  --var NAME=secret-ref   (recommended) inject one secret, YOU name the env var
  --derive-names          (deprecated) restore the old auto-derived behavior
See https://github.com/keyorixhq/keyorix/issues/1816 for why`)
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	projectName := runProject
	if projectName == "" {
		projectName = os.Getenv("KEYORIX_PROJECT")
	}
	if projectName == "" {
		projectName = "default"
	}

	secretsByName, err := fetchRunSecrets(ctx, client, projectName, runEnv)
	if err != nil {
		return err
	}

	derived, varMapped, err := resolveChildEnvVars(secretsByName, runVarMappings, runDeriveNames, projectName, runEnv)
	if err != nil {
		return err
	}

	return execChild(args, derived, varMapped, runCleanEnv)
}

// fetchRunSecrets resolves project+environment names to IDs, then pages through and fetches
// every secret's value in that scope, keyed by the secret's own raw name (env-var-key
// derivation happens later, in resolveChildEnvVars, only for the --derive-names path).
func fetchRunSecrets(ctx context.Context, client *apiclient.ClientWithResponses, project, env string) (map[string]string, error) { // NOSONAR -- cognitive complexity, matches the old CLI's remote path this mirrors
	projResp, err := client.ListProjectsWithResponse(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	if projResp.JSON200 == nil || projResp.JSON200.Data == nil {
		return nil, apiError("list projects", projResp.StatusCode(), projResp.Body)
	}
	var projectID int
	for _, p := range derefProjectSummarySlice(projResp.JSON200.Data.Projects) {
		if p.Name != nil && strings.EqualFold(*p.Name, project) {
			projectID = derefInt(p.Id)
			break
		}
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project %q not found", project)
	}

	envResp, err := client.ListProjectEnvironmentsWithResponse(ctx, uint32(projectID), nil) // #nosec G115 -- projectID resolved from the server's own listing, always positive
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	if envResp.JSON200 == nil || envResp.JSON200.Data == nil {
		return nil, apiError("list environments", envResp.StatusCode(), envResp.Body)
	}
	var envID int
	for _, e := range derefEnvironmentSlice(envResp.JSON200.Data.Environments) {
		if e.Name != nil && strings.EqualFold(*e.Name, env) {
			envID = derefInt(e.Id)
			break
		}
	}
	if envID == 0 {
		return nil, fmt.Errorf("environment %q not found in project %q", env, project)
	}

	// maxRunInjectedSecrets bounds the total number of secrets injected as child-process env
	// vars (#G44): with no cap, a project holding a very large number of secrets can exhaust
	// CLI memory fetching them one by one, or overrun the OS's environment-block size limit.
	const pageSize = 500
	const maxRunInjectedSecrets = 2000
	result := make(map[string]string)
	for page := 1; ; page++ {
		p, ps := page, pageSize
		pid, eid := projectID, envID
		listResp, err := client.ListSecretsWithResponse(ctx, &apiclient.ListSecretsParams{
			ProjectId: &pid, EnvironmentId: &eid, Page: &p, PageSize: &ps,
		})
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		if listResp.JSON200 == nil || listResp.JSON200.Data == nil {
			return nil, apiError("list secrets", listResp.StatusCode(), listResp.Body)
		}
		secrets := derefSecretListEntrySlice(listResp.JSON200.Data.Secrets)
		if len(result)+len(secrets) > maxRunInjectedSecrets {
			return nil, fmt.Errorf("project %q/environment %q has more than %d secrets -- 'keyorix-next run' injects every secret as an env var and refuses to continue past this cap; narrow the environment or use a different injection method", project, env, maxRunInjectedSecrets)
		}
		for _, s := range secrets {
			id := derefInt(s.ID)
			name := derefStr(s.Name)
			includeValue := true
			getResp, err := client.GetSecretWithResponse(ctx, id, &apiclient.GetSecretParams{IncludeValue: &includeValue})
			if err != nil || getResp.JSON200 == nil || getResp.JSON200.Data == nil || getResp.JSON200.Data.Value == nil {
				fmt.Fprintf(os.Stderr, "warning: skipping secret %q (id=%d): could not fetch value\n", name, id)
				continue
			}
			result[name] = *getResp.JSON200.Data.Value
		}
		if len(secrets) < pageSize {
			break
		}
	}
	return result, nil
}

func derefProjectSummarySlice[T any](s *[]T) []T {
	if s == nil {
		return nil
	}
	return *s
}

func derefEnvironmentSlice(s *[]apiclient.Environment) []apiclient.Environment {
	if s == nil {
		return nil
	}
	return *s
}

// ── Helpers (identical logic to the old CLI's internal/cli/run -- pure, no storage/network) ──

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

func setEnvKey(result map[string]string, envKeySources map[string]string, name, value string) error {
	key := toEnvKey(name)
	if existing, ok := envKeySources[key]; ok && existing != name {
		return fmt.Errorf("secrets %q and %q both sanitize to the same environment variable %q -- 'keyorix-next run' refuses to continue since one of them would silently be dropped from the child process's environment; rename one of the secrets to avoid the collision", existing, name, key)
	}
	envKeySources[key] = name
	result[key] = value
	return nil
}

// dangerousEnvPrefixes/dangerousEnvExact: reserved dynamic-linker/interpreter/shell control
// variables a --derive-names secret name must never be allowed to become (CLI-RUN-001,
// #1816). See the old CLI's internal/cli/run/run.go for the full per-family rationale --
// unchanged here, this is security logic, not something to redo from memory.
var dangerousEnvPrefixes = []string{
	"LD_", "DYLD_", "NODE_", "PYTHON", "PERL5", "BASH_", "GCONV_", "MALLOC_",
}

var dangerousEnvExact = map[string]bool{
	"IFS": true, "ENV": true, "HOME": true, "SHELL": true, "PATH": true,
	"RUBYOPT": true, "GIT_SSH_COMMAND": true,
}

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

func dropDangerousEnvKeys(envVars map[string]string) map[string]string {
	out := make(map[string]string, len(envVars))
	for key, value := range envVars {
		if isDangerousEnvKey(key) {
			fmt.Fprintf(os.Stderr, "WARNING: a secret maps to the reserved environment variable %q -- refusing to inject it (would override %s in the launched process)\n", key, key)
			continue
		}
		out[key] = value
	}
	return out
}

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

func resolveChildEnvVars(secretsByName map[string]string, varMappings []string, deriveNames bool, project, env string) (derived, varMapped map[string]string, err error) {
	if deriveNames {
		fmt.Fprintln(os.Stderr, "WARNING: --derive-names is deprecated: the env var name comes from each secret's own NAME. Prefer --var NAME=secret-ref, where you choose the name. See https://github.com/keyorixhq/keyorix/issues/1816.")
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
		varSources := make(map[string]string, len(varMappings))
		for _, mapping := range varMappings {
			envName, secretRef, ok := strings.Cut(mapping, "=")
			if !ok || envName == "" || secretRef == "" {
				return nil, nil, fmt.Errorf("invalid --var %q: expected NAME=secret-ref", mapping)
			}
			if !isValidEnvVarName(envName) {
				return nil, nil, fmt.Errorf("invalid --var %q: %q is not a valid environment variable name", mapping, envName)
			}
			if existingRef, ok := varSources[envName]; ok && existingRef != secretRef {
				return nil, nil, fmt.Errorf("--var %s is assigned to two different secrets (%q and %q) -- 'keyorix-next run' refuses to continue since one mapping would silently be dropped; use --var only once per name", envName, existingRef, secretRef)
			}
			value, ok := secretsByName[secretRef]
			if !ok {
				return nil, nil, fmt.Errorf("--var %s=%s: secret %q not found in project %q / environment %q", envName, secretRef, secretRef, project, env)
			}
			if isDangerousEnvKey(envName) {
				fmt.Fprintf(os.Stderr, "WARNING: --var maps secret %q onto %q, a reserved environment variable -- proceeding because you asked for it explicitly; double-check this is intentional\n", secretRef, envName)
			}
			varSources[envName] = secretRef
			vm[envName] = value
		}
		varMapped = vm
	}

	return derived, varMapped, nil
}

var sensitiveEnvSuffixes = []string{"_TOKEN", "_PASSWORD", "_SECRET", "_API_KEY", "_DSN", "_KEK"}

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

func execChild(args []string, derived, varMapped map[string]string, cleanEnv bool) error {
	childEnv := buildChildEnv(derived, varMapped, cleanEnv)

	c := exec.Command(args[0], args[1:]...) // #nosec G204 -- operator-supplied command, the whole point of `run` // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- same reasoning: operator-supplied command, not unverified user data
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

func buildChildEnv(derived, varMapped map[string]string, cleanEnv bool) []string {
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
			fmt.Fprintf(os.Stderr, "WARNING: a --derive-names secret maps to %q, which is already set in the inherited environment -- keeping the inherited value (use --var if this secret should take precedence)\n", k)
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
