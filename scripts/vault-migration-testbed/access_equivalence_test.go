//go:build e2e && e2e_containers

// access_equivalence_test.go is ADR-114 item 4 (docs/adr-114-vault-access-model-migration.md):
// for a migrated identity, Keyorix's granted read access must never exceed what Vault's own
// sys/capabilities-self says the source Vault principal could read — the machine-checked proof
// behind ADR-114's "narrower than Vault, never wider" governing rule, run here against MIG-1's
// own seeded messy Vault (./seed.sh) rather than a synthetic fixture.
//
// Scope, stated rather than silently narrower than ADR-114's own text: this check targets the
// AppRole-sourced identity only. seed.sh's one Kubernetes auth role
// (mig1-k8s-role) is bound_service_account_names="*" — a wildcard — which ADR-114's own mapping
// table classifies Unmappable (no machine identity is ever proposed for it), so there is no
// Kubernetes-sourced identity in this seed to equivalence-check. userpass is never migrated as a
// credential at all (ADR-114), so there is nothing to check there either.
//
// seed.sh's one AppRole role, mig1-migrator, holds exactly one policy (mig1-glob-readonly:
// `path "secret/data/*" { capabilities = ["read","list"] }`) — a glob landing exactly on the
// project-segment position, Unmappable under plan-access's DEFAULT path convention by design
// (ADR-114: a bare mount-wide wildcard is never auto-resolved to "every current project," which
// would be the forbidden superset). --path-map is precisely the escape hatch for this shape;
// this test uses it to resolve "secret/data/*" to one dedicated project/environment, exactly
// the way an operator migrating this real Vault would.
package vaultfidelity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

func TestAccessEquivalence_AppRoleGrantNeverExceedsVault(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv(n4ContainersOptInEnvVar) != "" {
			t.Fatalf("docker not available, but %s is set -- this job opted into the container tier and must not silently skip", n4ContainersOptInEnvVar)
		}
		t.Skip("docker not available -- skipping container-based access-equivalence check")
	}

	env := seedVault(t, backendName(), seedSize())
	migrateBin := buildMigrateBinary(t)
	serverBin, cliBin := harness.BuildBinaries(t)

	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)
	adminTok := adminLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminTok)

	const projectName = "mig1-access-equiv"
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projectName)
	projID := projectID(t, s, adminTok, projectName)
	envID := environmentID(t, s, adminTok, projID, "production") // one of "project create"'s seeded defaults.
	pat := createAdminPAT(t, cliBin, aEnv, "mig1-access-equiv-pat")

	// Import the actual secret VALUES into the same project/environment the access migration
	// targets below -- otherwise there is nothing real in Keyorix to check read-access
	// against, and this check would be vacuous.
	runMigrateBin(t, migrateBin, nil, "vault",
		"--vault-addr", env.addr, "--vault-token", env.token, "--vault-mount", "secret", "--vault-path", "",
		"--server", s.BaseURL, "--token", pat,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--apply")

	pathMap := fmt.Sprintf("secret/data=%d:%d", projID, envID)
	planPrefix := filepath.Join(t.TempDir(), "access-plan")
	runMigrateBin(t, migrateBin, nil, "vault", "plan-access",
		"--vault-addr", env.addr, "--vault-token", env.token,
		"--server", s.BaseURL, "--token", pat,
		"--path-map", pathMap, "--output", planPrefix)

	credsPath := filepath.Join(t.TempDir(), "creds.txt")
	runMigrateBin(t, migrateBin, nil, "vault", "apply-access",
		"--vault-addr", env.addr, "--vault-token", env.token,
		"--server", s.BaseURL, "--token", pat,
		"--path-map", pathMap, "--plan", planPrefix+".json", "--credentials-out", credsPath)

	// ── Vault side: mint a REAL token for mig1-migrator and ask Vault itself what it can
	// read -- not this test's own (or migrate's own) interpretation of the policy text.
	roleID := vaultAppRoleRoleID(t, env.addr, env.token, "mig1-migrator")
	secretID := vaultAppRoleSecretID(t, env.addr, env.token, "mig1-migrator")
	migratorToken := vaultAppRoleLogin(t, env.addr, roleID, secretID)

	// ── Keyorix side: a project/environment-scoped secrets.read grant has no finer
	// sub-scope -- every secret currently in this project/environment is readable by the
	// migrated identity, full stop.
	keyorixNames := map[string]bool{}
	for _, se := range listSecrets(t, s, adminTok, projID, envID) {
		keyorixNames[se.Name] = true
	}

	// ── Walk the SAME Vault tree independently (not through migrate's own import path) and
	// cross-check every leaf.
	leaves := walkVaultKVv2(t, env.addr, env.token, "secret", "")
	if len(leaves) == 0 {
		t.Fatal("walked zero leaves under secret/ -- the comparison below would be vacuously true; this is a harness bug, not a clean pass")
	}

	var extraAccess, missingAccess []string
	for _, leaf := range leaves {
		vaultPath := "secret/data/" + leaf
		vaultAllowed := capabilitiesSelfAllowsRead(t, env.addr, migratorToken, vaultPath)
		name := wantName(leaf, "")
		inKeyorix := keyorixNames[name]
		switch {
		case inKeyorix && !vaultAllowed:
			extraAccess = append(extraAccess, fmt.Sprintf("%s (keyorix secret %q is readable; vault capabilities-self denies %s)", leaf, name, vaultPath))
		case vaultAllowed && !inKeyorix:
			missingAccess = append(missingAccess, leaf)
		}
	}

	if len(extraAccess) > 0 {
		t.Fatalf("ADR-114's governing rule violated -- Keyorix grants MORE read access than Vault did for %d path(s):\n%s",
			len(extraAccess), strings.Join(extraAccess, "\n"))
	}
	if len(missingAccess) > 0 {
		// Reported, not a failure (ADR-114: missing access is an expected, named gap --
		// e.g. a value-import skip for an oversized/soft-deleted fixture).
		t.Logf("gap (not a failure): %d Vault-readable path(s) have no corresponding Keyorix secret: %v", len(missingAccess), missingAccess)
	}

	// ── Negative control: a path in a DIFFERENT mount, never covered by mig1-migrator's
	// policy, must be denied. Proves this check actually discriminates -- a positive-control-
	// only check that happened to pass because every path was allowed would be exactly the
	// "always green, proves nothing" failure mode this repo's own CLAUDE.md warns about.
	if capabilitiesSelfAllowsRead(t, env.addr, migratorToken, "kv1-legacy/legacy/db-password") {
		t.Fatal("negative control failed: mig1-migrator must NOT be able to read kv1-legacy/legacy/db-password -- either seed.sh's policy changed, or this check's own capabilities-self call is broken")
	}
}

// ── Vault AppRole + capabilities-self helpers (small, hand-rolled, read/self-auth-only calls
// this harness needs that neither migrate's vaultsource/healthscan packages expose as a public
// API this test could import -- scripts/vault-migration-testbed cannot depend on migrate/,
// matching this file's own "module boundary" precedent for sanitizeSecretName/wantName above) ──

func vaultAppRoleRoleID(t *testing.T, addr, rootToken, role string) string {
	t.Helper()
	var body struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	vaultDo(t, http.MethodGet, addr, rootToken, "auth/approle/role/"+role+"/role-id", nil, &body)
	if body.Data.RoleID == "" {
		t.Fatalf("auth/approle/role/%s/role-id: empty role_id", role)
	}
	return body.Data.RoleID
}

func vaultAppRoleSecretID(t *testing.T, addr, rootToken, role string) string {
	t.Helper()
	var body struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	vaultDo(t, http.MethodPost, addr, rootToken, "auth/approle/role/"+role+"/secret-id", map[string]any{}, &body)
	if body.Data.SecretID == "" {
		t.Fatalf("auth/approle/role/%s/secret-id: empty secret_id", role)
	}
	return body.Data.SecretID
}

func vaultAppRoleLogin(t *testing.T, addr, roleID, secretID string) string {
	t.Helper()
	var body struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	vaultDo(t, http.MethodPost, addr, "", "auth/approle/login", map[string]any{"role_id": roleID, "secret_id": secretID}, &body)
	if body.Auth.ClientToken == "" {
		t.Fatal("auth/approle/login: empty client_token")
	}
	return body.Auth.ClientToken
}

// capabilitiesSelfAllowsRead asks Vault (via the token being tested, not root) whether it can
// "read" path. Vault's response shape for sys/capabilities-self differs for exactly one path
// (top-level "capabilities") vs. several (a map keyed by path) -- this helper always asks for
// exactly one path, so only the top-level-array shape is ever exercised.
func capabilitiesSelfAllowsRead(t *testing.T, addr, token, path string) bool {
	t.Helper()
	var body struct {
		Capabilities []string `json:"capabilities"`
	}
	vaultDo(t, http.MethodPost, addr, token, "sys/capabilities-self", map[string]any{"paths": []string{path}}, &body)
	for _, c := range body.Capabilities {
		if c == "read" {
			return true
		}
	}
	return false
}

// walkVaultKVv2 recursively lists a KV v2 mount's metadata tree and returns every leaf's
// mount-relative path. Single-field-leaf granularity only (matches wantName's own existing
// simplification in this file) -- a multi-field leaf's extra fields are not individually
// cross-checked, a stated limitation, not a silent gap.
func walkVaultKVv2(t *testing.T, addr, token, mount, root string) []string {
	t.Helper()
	var out []string
	var walk func(prefix string)
	walk = func(prefix string) {
		var list struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		status := vaultDoStatus(t, http.MethodGet, addr, token, mount+"/metadata/"+prefix+"?list=true", nil, &list)
		if status == http.StatusNotFound {
			return
		}
		for _, k := range list.Data.Keys {
			child := prefix + k
			if strings.HasSuffix(k, "/") {
				walk(child)
				continue
			}
			out = append(out, child)
		}
	}
	walk(strings.Trim(root, "/"))
	return out
}

func vaultDo(t *testing.T, method, addr, token, path string, reqBody any, out any) {
	t.Helper()
	status := vaultDoStatus(t, method, addr, token, path, reqBody, out)
	if status < 200 || status >= 300 {
		t.Fatalf("%s %s: HTTP %d", method, path, status)
	}
}

func vaultDoStatus(t *testing.T, method, addr, token, path string, reqBody, out any) int {
	t.Helper()
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("marshal request body for %s %s: %v", method, path, err)
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, addr+"/v1/"+path, bodyReader) // #nosec G107 -- addr is this test's own seed.sh-started container address
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		t.Fatalf("%s %s: read response: %v", method, path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode response: %v\nbody: %s", method, path, err, raw)
		}
	}
	return resp.StatusCode
}
