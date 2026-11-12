//go:build !windows

package encryption_test

// process_crash_recovery_world_test.go builds and observes one real install for
// FuzzProcessCrashRecovery: keyorix.yaml, key files and a SQLite database made by
// the real admin commands, reopened through the same steps a server boot takes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
)

const (
	pcrashExitHarness = 90 // a harness failure in the child, never an operation's verdict

	pcrashPass  = "pcrash-fuzz-passphrase-one-0001"
	pcrashPass2 = "pcrash-fuzz-passphrase-two-0002"
	pcrashPass3 = "pcrash-fuzz-passphrase-three-0003"

	pcrashSeedFile = "pcrash-seed.json"
	pcrashAdmin    = "pcrash-admin"
	pcrashAdminPw  = "PcrashFuzzAdmin123!"
	pcrashUserPw   = "PcrashFuzzUser123!"
	pcrashNewName  = "pcrash-created"
	pcrashNewValue = "pcrash-created-value"
	pcrashUpdValue = "pcrash-updated-value"
	pcrashNewRole  = "pcrash-custom-role"
	pcrashUpdName  = "pcrash-base-0"
)

// pcrashSeed is the fixed part of an install, written once by the "seed" action.
type pcrashSeed struct {
	ProjectID uint            `json:"project_id"`
	EnvID     uint            `json:"env_id"`
	AdminID   uint            `json:"admin_id"`
	Users     map[string]uint `json:"users"`
	Ledger    pcrashLedger    `json:"ledger"`
}

// pcrashLedger maps a secret's name to its plaintext values, oldest version first.
type pcrashLedger map[string][]string

func (l pcrashLedger) clone() pcrashLedger {
	o := make(pcrashLedger, len(l))
	for k, v := range l {
		o[k] = slices.Clone(v)
	}
	return o
}

// pcrashModel is everything the oracles compare between before, after and the
// state a killed process left.
type pcrashModel struct {
	Ledger pcrashLedger
	Roles  map[string][]string // role name -> sorted permission names
	Authz  map[string]bool     // pcrashProbes key -> decision
}

// pcrashInstall is one open install, reached through the steps of a server boot
// (server/boot_core.go, boot_encryption.go), in that order. A drift between the
// two is not detected by anything here.
type pcrashInstall struct {
	cfg   *config.Config
	store corestorage.Storage
	db    *gorm.DB
	svc   *encryption.Service
	core  *core.KeyorixCore
}

func openPCrashInstall(dir, pass string) (_ *pcrashInstall, err error) {
	cfg, err := config.Load(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	if !filepath.IsAbs(cfg.Storage.Database.Path) {
		cfg.Storage.Database.Path = filepath.Join(dir, cfg.Storage.Database.Path)
	}
	if err := i18n.Initialize(cfg); err != nil {
		return nil, fmt.Errorf("i18n: %w", err)
	}
	if err := restorejournal.RefuseIfPresent(cfg); err != nil {
		return nil, err
	}
	store, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("open storage: %w", err)
	}
	inst := &pcrashInstall{cfg: cfg, store: store}
	defer func() {
		if err != nil {
			inst.close()
		}
	}()
	inst.svc = encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := inst.svc.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("key lock: %w", err)
	}
	if err := inst.svc.ReconcileKeySet(); err != nil {
		return nil, fmt.Errorf("key file consistency: %w", err)
	}
	if inst.db, err = appstorage.OpenGormDB(cfg); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := inst.svc.RecoverInterruptedRotation(inst.db); err != nil {
		return nil, fmt.Errorf("rotation recovery: %w", err)
	}
	if err := inst.svc.Initialize(pass); err != nil {
		return nil, fmt.Errorf("%w: %w", errPCrashKey, err)
	}
	inst.core = core.NewKeyorixCore(store)
	inst.core.SetSecretValueEncryptor(inst.svc)
	inst.core.SetAuthEncryptor(inst.svc)
	if !inst.core.SecretValueEncryptionActive() {
		return nil, errors.New("secret-value encryption is not active: the value oracles would be vacuous")
	}
	return inst, nil
}

// errPCrashKey marks Initialize refusing the passphrase or the key files, which
// is how the parent learns a passphrase is not the install's current one.
var errPCrashKey = errors.New("key initialization refused")

func (i *pcrashInstall) close() {
	if i.svc != nil {
		i.svc.Shutdown()
	}
	if i.db != nil {
		if sqlDB, err := i.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
	if c, ok := i.store.(io.Closer); ok {
		_ = c.Close()
	}
}

// pcrashProbes is the fixed authorization probe set: every user, every
// permission, at every scope the fixture grants or could grant.
func pcrashProbes(s pcrashSeed) map[string]func(ctx context.Context, c *core.KeyorixCore) (bool, error) {
	probes := map[string]func(context.Context, *core.KeyorixCore) (bool, error){}
	scopes := map[string]core.Scope{
		"global":  {},
		"project": {ProjectID: s.ProjectID},
		"env":     {ProjectID: s.ProjectID, EnvironmentID: s.EnvID},
	}
	for user, id := range s.Users {
		for _, perm := range []string{"secrets.read", "secrets.write", "secrets.delete", "roles.manage"} {
			for scopeName, scope := range scopes {
				probes[user+"|"+perm+"|"+scopeName] = func(ctx context.Context, c *core.KeyorixCore) (bool, error) {
					return c.Authorize(ctx, id, perm, scope)
				}
			}
		}
	}
	return probes
}

// observe reads the whole model back. Any secret that cannot be decrypted is an
// error: that is the half-rotated state the fuzzer exists to catch.
func (i *pcrashInstall) observe(ctx context.Context, s pcrashSeed) (*pcrashModel, error) {
	m := &pcrashModel{Ledger: pcrashLedger{}, Roles: map[string][]string{}, Authz: map[string]bool{}}
	type nodeRow struct {
		ID   uint
		Name string
	}
	var nodes []nodeRow
	if err := i.db.Raw("SELECT id, name FROM secret_nodes WHERE deleted_at IS NULL AND is_secret = ?", true).Scan(&nodes).Error; err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	for _, n := range nodes {
		versions, err := i.core.GetSecretVersions(ctx, n.ID)
		if err != nil {
			return nil, fmt.Errorf("list versions of %q: %w", n.Name, err)
		}
		numbers := make([]int, 0, len(versions))
		for _, v := range versions {
			numbers = append(numbers, v.VersionNumber)
		}
		slices.Sort(numbers)
		values := make([]string, 0, len(numbers))
		for _, num := range numbers {
			val, err := i.core.GetSecretValueByVersion(ctx, n.ID, num)
			if err != nil {
				return nil, fmt.Errorf("read %q v%d: %w", n.Name, num, err)
			}
			values = append(values, string(val))
		}
		m.Ledger[n.Name] = values
	}
	type roleRow struct{ Role, Perm string }
	var rows []roleRow
	err := i.db.Raw(`SELECT r.name AS role, COALESCE(p.name, '') AS perm FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id`).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	for _, r := range rows {
		perms := m.Roles[r.Role]
		if perms == nil {
			perms = []string{}
		}
		if r.Perm != "" {
			perms = append(perms, r.Perm)
		}
		m.Roles[r.Role] = perms
	}
	for _, perms := range m.Roles {
		sort.Strings(perms)
	}
	for key, probe := range pcrashProbes(s) {
		ok, err := probe(ctx, i.core)
		if err != nil {
			return nil, fmt.Errorf("authz probe %s: %w", key, err)
		}
		m.Authz[key] = ok
	}
	return m, nil
}

// ciphertexts returns every live secret version's stored bytes by row id.
func (i *pcrashInstall) ciphertexts() (map[uint]string, error) {
	type row struct {
		ID             uint
		EncryptedValue []byte
	}
	var rows []row
	err := i.db.Raw(`SELECT v.id, v.encrypted_value FROM secret_versions v
		JOIN secret_nodes n ON n.id = v.secret_node_id WHERE n.deleted_at IS NULL`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[uint]string, len(rows))
	for _, r := range rows {
		out[r.ID] = string(r.EncryptedValue)
	}
	return out, nil
}

func readPCrashSeed(dir string) (pcrashSeed, error) {
	var s pcrashSeed
	b, err := os.ReadFile(filepath.Join(dir, pcrashSeedFile)) //nolint:gosec // test-generated path
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// addPCrashSecret creates a secret with values oldest first.
func addPCrashSecret(ctx context.Context, c *core.KeyorixCore, s pcrashSeed, name string, values []string) error {
	node, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: name, Value: []byte(values[0]), ProjectID: s.ProjectID, EnvironmentID: s.EnvID,
		Type: "generic", CreatedBy: pcrashAdmin, OwnerID: s.AdminID,
	})
	if err != nil {
		return fmt.Errorf("create %q: %w", name, err)
	}
	for _, v := range values[1:] {
		if _, err := c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: node.ID, Value: []byte(v), UpdatedBy: pcrashAdmin, UserID: s.AdminID}); err != nil {
			return fmt.Errorf("update %q: %w", name, err)
		}
	}
	return nil
}

// runPCrashSeedAction populates a freshly migrated install.
func runPCrashSeedAction(ctx context.Context, inst *pcrashInstall) error {
	c := inst.core
	const token = "pcrash-bootstrap-token"
	c.SetBootstrapToken(token)
	res, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: pcrashAdmin, Email: pcrashAdmin + "@example.com", Password: pcrashAdminPw, DisplayName: pcrashAdmin, Token: token,
	})
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	seed := pcrashSeed{AdminID: res.User.ID, Users: map[string]uint{}, Ledger: pcrashLedger{}}
	project, err := c.CreateProject(ctx, "pcrash-project", "")
	if err != nil {
		return fmt.Errorf("project: %w", err)
	}
	env, err := c.CreateEnvironment(ctx, project.ID, "pcrash-env")
	if err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	seed.ProjectID, seed.EnvID = project.ID, env.ID
	for _, name := range []string{"alice", "bob", "carol"} {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "pcrash-" + name, Email: name + "@example.com", DisplayName: name, Password: pcrashUserPw})
		if err != nil {
			return fmt.Errorf("user %s: %w", name, err)
		}
		seed.Users[name] = u.ID
	}
	scope := core.Scope{ProjectID: project.ID}
	if err := c.AssignUserRoleScoped(ctx, "alice@example.com", "project_viewer", scope); err != nil {
		return fmt.Errorf("grant alice: %w", err)
	}
	if err := c.AssignUserRoleScoped(ctx, "carol@example.com", "project_developer", scope); err != nil {
		return fmt.Errorf("grant carol: %w", err)
	}
	for n := range 3 {
		name := fmt.Sprintf("pcrash-base-%d", n)
		values := make([]string, n+1)
		for v := range values {
			values[v] = fmt.Sprintf("%s-value-%d", name, v+1)
		}
		if err := addPCrashSecret(ctx, c, seed, name, values); err != nil {
			return err
		}
		seed.Ledger[name] = values
	}
	b, err := json.Marshal(seed)
	if err != nil {
		return err
	}
	return os.WriteFile(pcrashSeedFile, b, 0o600)
}

// runPCrashCoreAction runs one core-level operation in the working directory.
func runPCrashCoreAction(ctx context.Context, action string) int {
	inst, err := openPCrashInstall(".", os.Getenv(envPCrashPass))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open install:", err)
		return pcrashExitHarness
	}
	defer inst.close()
	if action == "seed" {
		if err := runPCrashSeedAction(ctx, inst); err != nil {
			fmt.Fprintln(os.Stderr, "seed:", err)
			return pcrashExitHarness
		}
		return 0
	}
	if action == "rerun-panic" {
		panic("red-proof: a rerun that panics")
	}
	if action == "rerun-corrupt" {
		// Red-proof only: a rerun that exits 0 having silently lost a secret.
		if err := inst.db.Exec("DELETE FROM secret_versions WHERE secret_node_id = (SELECT id FROM secret_nodes WHERE name = ?)", pcrashUpdName).Error; err != nil {
			fmt.Fprintln(os.Stderr, "corrupt:", err)
			return pcrashExitHarness
		}
		return 0
	}
	seed, err := readPCrashSeed(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed file:", err)
		return pcrashExitHarness
	}
	c := inst.core
	scope := core.Scope{ProjectID: seed.ProjectID}
	switch action {
	case "secret-create":
		err = addPCrashSecret(ctx, c, seed, pcrashNewName, []string{pcrashNewValue})
	case "secret-update":
		var id uint
		if err = inst.db.Raw("SELECT id FROM secret_nodes WHERE name = ? AND deleted_at IS NULL", pcrashUpdName).Scan(&id).Error; err == nil {
			_, err = c.UpdateSecret(ctx, &core.UpdateSecretRequest{ID: id, Value: []byte(pcrashUpdValue), UpdatedBy: pcrashAdmin, UserID: seed.AdminID})
		}
	case "role-grant":
		err = c.AssignUserRoleScoped(ctx, "bob@example.com", "project_developer", scope)
	case "role-revoke":
		err = c.RemoveUserRoleScoped(ctx, "alice@example.com", "project_viewer", scope)
	case "role-create":
		var ids []uint
		if err = inst.db.Raw("SELECT id FROM permissions WHERE name IN ('secrets.read', 'secrets.write')").Scan(&ids).Error; err == nil {
			_, _, err = c.CreateRole(ctx, seed.AdminID, pcrashNewRole, "fuzz", ids)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown action", action)
		return pcrashExitHarness
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}
