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
	runEnv     string
	runProject string
	runToken   string
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

Each secret name is uppercased and non-alphanumeric characters are
replaced with underscores before becoming an env var key:

  db-password  →  DB_PASSWORD
  api.endpoint →  API_ENDPOINT

Authentication:
  • Session tokens written by 'keyorix auth login' are used automatically
    when the CLI is in client mode.
  • For service accounts / CI/CD, set KEYORIX_TOKEN (or --token) and
    point the CLI at a server with 'keyorix connect' or KEYORIX_SERVER.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runRun,
}

func init() {
	RunCmd.Flags().StringVar(&runEnv, "env", "development", "Environment name (e.g. production)")
	RunCmd.Flags().StringVar(&runProject, "project", "default", "Project / namespace name")
	RunCmd.Flags().StringVar(&runToken, "token", "", "Service or session token (overrides KEYORIX_TOKEN env var)")
}

func runRun(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	var (
		envVars map[string]string
		err     error
	)

	// --token flag overrides the token resolved by ResolveRemote.
	endpoint, tok, remoteOK := common.ResolveRemote()
	if runToken != "" {
		tok = runToken
		remoteOK = endpoint != ""
	}

	if remoteOK {
		envVars, err = fetchSecretsRemote(ctx, endpoint, tok, runProject, runEnv)
	} else {
		envVars, err = fetchSecretsEmbedded(ctx, runProject, runEnv)
	}
	if err != nil {
		return err
	}

	return execChild(args, envVars)
}

// ── Embedded mode ─────────────────────────────────────────────────────────────

// fetchSecretsEmbedded uses the local core service (direct DB access).
func fetchSecretsEmbedded(ctx context.Context, project, env string) (map[string]string, error) {
	svc, err := common.InitializeCoreService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service: %w", err)
	}

	// Resolve namespace → ID
	namespaces, err := svc.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}
	var nsID uint
	for _, ns := range namespaces {
		if strings.EqualFold(ns.Name, project) {
			nsID = ns.ID
			break
		}
	}
	if nsID == 0 {
		return nil, fmt.Errorf("namespace %q not found", project)
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

	// List all secrets in the namespace + environment
	filter := &coreStorage.SecretFilter{
		NamespaceID:   &nsID,
		EnvironmentID: &envID,
		Page:          1,
		PageSize:      1000,
	}
	secrets, _, err := svc.ListSecrets(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	result := make(map[string]string, len(secrets))
	for _, s := range secrets {
		val, err := svc.GetSecretValue(ctx, s.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping secret %q (id=%d): %v\n", s.Name, s.ID, err)
			continue
		}
		result[toEnvKey(s.Name)] = string(val)
	}
	return result, nil
}

// ── Remote / client mode ──────────────────────────────────────────────────────

// apiClient makes authenticated requests to the Keyorix HTTP API.
// It handles the server's {"data": ...} envelope directly so it is not
// affected by the Success flag mismatch in the shared remote storage client.
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
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}

	// Server wraps every success response in {"data": ...}
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
func fetchSecretsRemote(ctx context.Context, endpoint, token, project, env string) (map[string]string, error) {
	api := &apiClient{
		endpoint: endpoint,
		token:    token,
		http:     &http.Client{},
	}

	// ── 1. Resolve namespace name → ID ────────────────────────────────────────
	var nsBody struct {
		Namespaces []*models.Namespace `json:"namespaces"`
	}
	if err := api.get(ctx, "/api/v1/namespaces", &nsBody); err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	var nsID uint
	for _, ns := range nsBody.Namespaces {
		if strings.EqualFold(ns.Name, project) {
			nsID = ns.ID
			break
		}
	}
	if nsID == 0 {
		return nil, fmt.Errorf("namespace %q not found on server", project)
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

	// ── 3. List secrets ────────────────────────────────────────────────────────
	listPath := fmt.Sprintf(
		"/api/v1/secrets?namespace_id=%d&environment_id=%d&page_size=1000&page=1",
		nsID, envID,
	)
	// The list endpoint returns SecretWithSharingInfo; we only need ID + Name.
	var secretsBody struct {
		Secrets []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := api.get(ctx, listPath, &secretsBody); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	// ── 4. Fetch each secret's decrypted value ─────────────────────────────────
	// GET /api/v1/secrets/{id}?include_value=true returns:
	//   {"secret": {...}, "value": "plaintext"}
	result := make(map[string]string, len(secretsBody.Secrets))
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
	return result, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// toEnvKey converts a secret name to a valid environment variable key.
//
//	"db-password"   → "DB_PASSWORD"
//	"api.endpoint"  → "API_ENDPOINT"
//	"MY SECRET"     → "MY_SECRET"
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

// execChild builds the child environment and executes the command.
// It propagates the child's exit code exactly.
func execChild(args []string, extraEnv map[string]string) error {
	childEnv := os.Environ()
	for k, v := range extraEnv {
		childEnv = append(childEnv, k+"="+v)
	}

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
