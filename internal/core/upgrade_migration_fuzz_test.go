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
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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
		ctx := context.Background()

		// Oracle 1: every secret decrypts to its recorded plaintext.
		for idStr, want := range manifest.SecretValues {
			var id uint
			if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
				t.Fatalf("manifest secret id %q: %v", idStr, err)
			}
			got, err := c.GetSecretValue(ctx, id)
			if err != nil {
				t.Fatalf("GetSecretValue(%d) after migrating a %s-vintage database: %v", id, manifest.SourceTag, err)
			}
			if string(got) != want {
				t.Errorf("secret %d decrypted to %q after migration, want %q (source=%s)", id, got, want, manifest.SourceTag)
			}
		}

		// Oracle 2: the fixed authz probe gives the same verdict the OLD
		// tag's own core.Authorize recorded at seed time.
		allowRead, err := c.Authorize(ctx, manifest.ProbeUserID, "secrets.read", Scope{ProjectID: manifest.ProbeProjectID})
		if err != nil {
			t.Fatalf("Authorize(read) after migration: %v", err)
		}
		if allowRead != manifest.ProbeAllowRead {
			t.Errorf("secrets.read verdict changed after migrating a %s-vintage database: was %v, now %v",
				manifest.SourceTag, manifest.ProbeAllowRead, allowRead)
		}
		allowWrite, err := c.Authorize(ctx, manifest.ProbeUserID, "secrets.write", Scope{ProjectID: manifest.ProbeProjectID})
		if err != nil {
			t.Fatalf("Authorize(write) after migration: %v", err)
		}
		if allowWrite != manifest.ProbeAllowWrite {
			t.Errorf("secrets.write verdict changed after migrating a %s-vintage database: was %v, now %v",
				manifest.SourceTag, manifest.ProbeAllowWrite, allowWrite)
		}

		// Oracle 3: the audit hash chain still verifies.
		verification, err := c.VerifyAuditChain(ctx)
		if err != nil {
			t.Fatalf("VerifyAuditChain after migration: %v", err)
		}
		if !verification.Valid {
			t.Errorf("audit chain failed to verify after migrating a %s-vintage database: first broken id=%v (chained=%d, unchained=%d)",
				manifest.SourceTag, verification.FirstBrokenID, verification.ChainedEvents, verification.UnchainedEvents)
		}

		// Oracle 4: no orphan rows introduced by migration.
		assertNoOrphans(t, dbPath, manifest.SourceTag)
	})
}

// assertNoOrphans opens dbPath directly (read-only, raw SQL) and checks
// every foreign-key-shaped reference this schema is documented to have
// resolves to a live parent row -- the migration's own job is additive
// schema changes plus any data backfill it performs; either one leaving a
// dangling reference behind is exactly what this oracle exists to catch.
func assertNoOrphans(t *testing.T, dbPath, sourceTag string) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("reopening %s for orphan check: %v", dbPath, err)
	}
	if sqlDB, err := db.DB(); err == nil {
		defer func() { _ = sqlDB.Close() }()
	}

	checks := []struct {
		desc  string
		query string
	}{
		{"SecretVersion with no parent SecretNode",
			"SELECT COUNT(*) FROM secret_versions sv LEFT JOIN secret_nodes sn ON sv.secret_node_id = sn.id WHERE sn.id IS NULL"},
		{"UserRole with no parent User",
			"SELECT COUNT(*) FROM user_roles ur LEFT JOIN users u ON ur.user_id = u.id WHERE u.id IS NULL"},
		{"UserRole with no parent Role",
			"SELECT COUNT(*) FROM user_roles ur LEFT JOIN roles r ON ur.role_id = r.id WHERE r.id IS NULL"},
		{"RolePermission with no parent Role",
			"SELECT COUNT(*) FROM role_permissions rp LEFT JOIN roles r ON rp.role_id = r.id WHERE r.id IS NULL"},
	}
	for _, c := range checks {
		var count int64
		if err := db.Raw(c.query).Scan(&count).Error; err != nil {
			t.Fatalf("orphan check %q: %v", c.desc, err)
		}
		if count > 0 {
			t.Errorf("%d orphan row(s) after migrating a %s-vintage database: %s", count, sourceTag, c.desc)
		}
	}
}
