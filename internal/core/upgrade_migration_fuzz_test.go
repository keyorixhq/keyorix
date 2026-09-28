// upgrade_migration_fuzz_test.go -- FUZZ-MECH M3: upgrade/migration fuzzing.
// Each of testdata/upgrade-fixtures/{v093,v094,v095} is a REAL SQLite
// database (plus its own encryption key files) built by that exact tag's
// own core.KeyorixCore -- bootstrapped, 5 secrets with known plaintext
// values (real AEAD-encrypted at rest, via SetSecretValueEncryptor, not
// left in the fail-open plaintext mode), a second user holding the seeded
// "viewer" role at project scope, and its own manifest.json recording the
// expected post-migration values (see the generator, kept in this file's
// git history / PR description, not committed -- these are OUTPUT
// fixtures, not a live generator).
//
// Per iteration: copy one fixture into a scratch dir, run HEAD's REAL
// production migration path (storage.NewStorageFactory().CreateStorage,
// the exact same createLocalStorage -> migrateDatabase call server
// startup makes -- not AutoMigrate called directly, which would test a
// weaker claim), then check:
//  1. Every secret decrypts to its recorded plaintext (encryption.Service
//     wired identically to production, same passphrase).
//  2. A fixed authorization probe (does the "viewer" project member hold
//     secrets.read / lack secrets.write) gives the SAME verdict recorded
//     at seed time under that OLD tag's own core.Authorize.
//  3. The audit hash chain (VerifyAuditChain) still verifies.
//  4. No orphan rows: every SecretVersion references a live SecretNode,
//     every UserRole references a live User and Role.
//
// v1 scope: 3 real fixtures (v0.93.0, v0.94.0, v0.95.0 -- confirmed
// unchanged models.go between v0.93.0/v0.94.0; only internal/storage/
// models/models.go's RecoveryKeyRecord + a factory.go migration-path
// refactor differ by v0.95.0/HEAD, per the diff checked before building
// this harness) rather than a byte-mutation fuzzer: mutating the copied
// SQLite file's bytes directly would produce corruption unrelated to
// migration-specific bugs (a decrypt failure from a flipped ciphertext
// byte is not a migration defect), which would be an unsound oracle for
// this specific claim. The fuzz input selects which of the 3 real
// fixtures to run -- small input space, but every value is a real,
// independently-generated historical database, not a synthetic case.
//
// This file covers SQLite. See upgrade_migration_pg_replay_test.go
// (FuzzUpgradeMigrationPostgres, E4) for the Postgres path: it replays each
// fixture's own pre-migration schema and row data into an isolated Postgres
// schema, then runs the exact same 4 oracles (runUpgradeOracles) there too.
package core

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type upgradeFuzzManifest struct {
	SourceTag       string            `json:"source_tag"`
	SecretValues    map[string]string `json:"secret_values"`
	ProbeUserID     uint              `json:"probe_user_id"`
	ProbeProjectID  uint              `json:"probe_project_id"`
	ProbeAllowRead  bool              `json:"probe_allow_read"`
	ProbeAllowWrite bool              `json:"probe_allow_write"`
	AdminUserID     uint              `json:"admin_user_id"`
	Passphrase      string            `json:"passphrase"`
}

var upgradeFuzzFixtures = []string{"v093", "v094", "v095"}

func copyFileT(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("opening %s: %v", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("creating %s: %v", dst, err)
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copying %s -> %s: %v", src, dst, err)
	}
}

func loadUpgradeFuzzManifest(t *testing.T, path string) upgradeFuzzManifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading manifest %s: %v", path, err)
	}
	var m upgradeFuzzManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decoding manifest %s: %v", path, err)
	}
	return m
}

// FuzzUpgradeMigration is FUZZ-MECH M3. See the package doc comment above.
func FuzzUpgradeMigration(f *testing.F) {
	for i := range upgradeFuzzFixtures {
		f.Add(uint8(i))
	}

	f.Fuzz(func(t *testing.T, sel uint8) {
		name := upgradeFuzzFixtures[int(sel)%len(upgradeFuzzFixtures)]
		srcDir := filepath.Join("testdata", "upgrade-fixtures", name)
		if _, err := os.Stat(srcDir); err != nil {
			t.Skipf("fixture %s not present: %v", name, err)
		}
		manifest := loadUpgradeFuzzManifest(t, filepath.Join(srcDir, "manifest.json"))

		workDir := t.TempDir()
		dbPath := filepath.Join(workDir, "fixture.db")
		copyFileT(t, filepath.Join(srcDir, "fixture.db"), dbPath)
		copyFileT(t, filepath.Join(srcDir, "dek.key"), filepath.Join(workDir, "dek.key"))
		copyFileT(t, filepath.Join(srcDir, "kek.salt"), filepath.Join(workDir, "kek.salt"))

		cfg := &config.Config{
			Storage: config.StorageConfig{
				Type:     "local",
				Database: config.DatabaseConfig{Path: dbPath},
				Encryption: config.EncryptionConfig{
					Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt",
				},
			},
		}

		// The real production migration path -- exactly what server startup
		// calls (createLocalStorage -> migrateDatabase), not AutoMigrate
		// called directly, which would test a weaker claim than "the actual
		// upgrade path this server ships".
		st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
		if err != nil {
			t.Fatalf("CreateStorage (real migration path) failed on a %s-vintage database: %v", manifest.SourceTag, err)
		}

		enc := encryption.NewService(&cfg.Storage.Encryption, workDir)
		if err := enc.Initialize(manifest.Passphrase); err != nil {
			t.Fatalf("re-opening the encryption service with the fixture's own passphrase: %v", err)
		}

		c := NewKeyorixCore(st)
		c.SetAuthEncryptor(enc)
		c.SetSecretValueEncryptor(enc)

		// Oracles 1-4: shared with FuzzUpgradeMigrationPostgres (E4) via
		// runUpgradeOracles, so the two backends can never silently diverge
		// in what they check -- see upgrade_migration_pg_replay_test.go.
		orphanDB, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("reopening %s for orphan check: %v", dbPath, err)
		}
		if sqlDB, e := orphanDB.DB(); e == nil {
			defer func() { _ = sqlDB.Close() }()
		}
		runUpgradeOracles(t, c, orphanDB, manifest)
	})
}
