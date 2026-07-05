package encryption

// rotate_e2e_test.go — End-to-end DEK rotation integration test (ADR-010, "Test 5").
//
// The unit tests in internal/encryption/sweep_test.go drive RotateDEKWithSweep
// directly against an in-memory SQLite DB and only seed secret_versions. This
// test closes the gap called out there ("Test 5 (end-to-end with real server)
// is an integration test — not here") by exercising the *CLI entry point*
// rotateWithConfig() end to end against a real on-disk database, with every
// DEK-encrypted table populated:
//
//   - secret_versions  (one AAD-bound row + one legacy pre-AAD row)
//   - sessions
//   - api_tokens
//   - api_clients
//   - password_resets
//
// It asserts the full ADR-010 acceptance criteria:
//  1. every row re-encrypts — the rotated on-disk DEK decrypts all of them;
//  2. the old DEK no longer decrypts any row;
//  3. legacy (no-AAD) secret rows are upgraded to AAD v2;
//  4. dek.key.backup.* files left by the deprecated RotateDEK are deleted;
//  5. the dek.key.pending file is cleaned up.
//
// Backends: the test always runs against a real on-disk SQLite file (so it is
// part of normal CI, which has no Postgres service). When KEYORIX_TEST_PG_DSN
// is set it additionally runs against Postgres in an isolated, auto-dropped
// schema — that is how the sweep is verified against the production driver.
//
//   KEYORIX_TEST_PG_DSN="host=localhost port=5432 dbname=keyorix user=keyorix sslmode=disable password=keyorix123" \
//     go test ./internal/cli/encryption/ -run EndToEnd -v

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	enc "github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const e2ePassphrase = "e2e-test-passphrase-correct-horse-battery"

// seeded plaintexts, one per encrypted column.
const (
	e2eProjectID  = uint(7)
	ptAADSecret   = "aad-secret-plaintext-value"
	ptLegacy      = "legacy-secret-plaintext-value"
	ptSession     = "session-token-plaintext"
	ptAPIToken    = "api-token-plaintext"
	ptAPIClient   = "client-secret-plaintext"
	ptPasswordRst = "password-reset-token-plaintext"
)

func TestRotateDEKWithSweep_EndToEnd(t *testing.T) {
	for _, kind := range e2eBackends(t) {
		t.Run(kind, func(t *testing.T) {
			runRotationE2E(t, kind)
		})
	}
}

// e2eBackends returns the database backends to exercise: always sqlite; plus
// postgres when KEYORIX_TEST_PG_DSN is set.
func e2eBackends(t *testing.T) []string {
	t.Helper()
	backends := []string{"sqlite"}
	if os.Getenv("KEYORIX_TEST_PG_DSN") != "" {
		backends = append(backends, "postgres")
	} else {
		t.Log("KEYORIX_TEST_PG_DSN not set — skipping the Postgres backend (sqlite only)")
	}
	return backends
}

func runRotationE2E(t *testing.T, kind string) {
	// rotateWithConfig resolves the key directory from os.Getwd(); point it at a
	// throwaway dir holding kek.salt + dek.key. t.Chdir restores cwd at the end.
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", e2ePassphrase)

	cfg := &config.Config{}
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	openDB := configureBackend(t, kind, cfg, workDir)

	// 1. Initialise encryption on disk. oldSvc keeps the *old* DEK live in memory
	//    so it can serve as the "old key must fail" oracle after rotation.
	oldSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := oldSvc.Initialize(e2ePassphrase); err != nil {
		t.Fatalf("initialise encryption: %v", err)
	}
	defer oldSvc.Shutdown()

	// 2. Migrate + seed every encrypted table, encrypting with the old DEK.
	db := openDB()
	if err := db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Session{},
		&models.APIToken{}, &models.APIClient{}, &models.PasswordReset{},
		&models.MFASecret{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	// secret_versions: one AAD-bound row...
	aadNode := &models.SecretNode{ProjectID: e2eProjectID, Name: "e2e-aad-node", IsSecret: true}
	mustCreate(t, db, aadNode)
	aadAAD := enc.SecretAAD(aadNode.ID, e2eProjectID, 1)
	aadVal, aadMeta := mustEncryptAAD(t, oldSvc, ptAADSecret, aadAAD)
	aadVer := &models.SecretVersion{SecretNodeID: aadNode.ID, VersionNumber: 1, EncryptedValue: aadVal, EncryptionMetadata: models.JSON(aadMeta)}
	mustCreate(t, db, aadVer)

	// ...and one legacy (pre-AAD) row that the sweep must upgrade to v2.
	legacyNode := &models.SecretNode{ProjectID: e2eProjectID, Name: "e2e-legacy-node", IsSecret: true}
	mustCreate(t, db, legacyNode)
	legacyVal, legacyMeta := mustEncrypt(t, oldSvc, ptLegacy)
	legacyVer := &models.SecretVersion{SecretNodeID: legacyNode.ID, VersionNumber: 1, EncryptedValue: legacyVal, EncryptionMetadata: models.JSON(legacyMeta)}
	mustCreate(t, db, legacyVer)
	// after the sweep the upgraded row is AAD-bound to (nodeID, projectID, version):
	legacyAAD := enc.SecretAAD(legacyNode.ID, e2eProjectID, 1)

	// auth tables — all use plain (no-AAD) encryption, the same blob format
	// EncryptSecret produces, which is what the auth sweepers read back.
	sessVal, sessMeta := mustEncrypt(t, oldSvc, ptSession)
	session := &models.Session{UserID: 1, SessionToken: "e2e-dep-session", EncryptedSessionToken: sessVal, SessionTokenMetadata: models.JSON(sessMeta)}
	mustCreate(t, db, session)

	tokVal, tokMeta := mustEncrypt(t, oldSvc, ptAPIToken)
	apiToken := &models.APIToken{ClientID: 1, Token: "e2e-dep-token", EncryptedToken: tokVal, TokenMetadata: models.JSON(tokMeta)}
	mustCreate(t, db, apiToken)

	cliVal, cliMeta := mustEncrypt(t, oldSvc, ptAPIClient)
	apiClient := &models.APIClient{Name: "e2e-client", ClientID: "e2e-dep-client", EncryptedClientSecret: cliVal, ClientSecretMetadata: models.JSON(cliMeta)}
	mustCreate(t, db, apiClient)

	prVal, prMeta := mustEncrypt(t, oldSvc, ptPasswordRst)
	passwordReset := &models.PasswordReset{UserID: 1, Token: "e2e-dep-reset", EncryptedToken: prVal, TokenMetadata: models.JSON(prMeta)}
	mustCreate(t, db, passwordReset)

	// Release the seed connection before rotation (SQLite is single-writer; the
	// CLI opens its own connection inside rotateWithConfig).
	closeGorm(db)

	// 3. Drop in fake backup files that a previous deprecated RotateDEK would
	//    have left behind — the sweep must delete them on success.
	for _, suffix := range []string{"100", "200"} {
		p := filepath.Join(workDir, "dek.key.backup."+suffix)
		if err := os.WriteFile(p, []byte("stale-wrapped-dek"), 0600); err != nil {
			t.Fatalf("write fake backup %s: %v", p, err)
		}
	}

	// 4. Rotate through the real CLI entry point.
	if err := rotateWithConfig(cfg, true, false); err != nil {
		t.Fatalf("rotateWithConfig: %v", err)
	}

	// 5. Verify. A fresh Service initialised from the rotated on-disk key proves
	//    the new DEK was promoted to dek.key and persisted (survives a restart).
	newSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := newSvc.Initialize(e2ePassphrase); err != nil {
		t.Fatalf("re-initialise from rotated key: %v", err)
	}
	defer newSvc.Shutdown()

	db = openDB()
	defer closeGorm(db)

	// secret_versions — AAD-bound row.
	var gotAAD models.SecretVersion
	mustFirst(t, db, &gotAAD, aadVer.ID)
	if pt, err := newSvc.DecryptSecretWithAAD(gotAAD.EncryptedValue, aadAAD); err != nil {
		t.Errorf("aad secret: new DEK decrypt failed: %v", err)
	} else if string(pt) != ptAADSecret {
		t.Errorf("aad secret: got %q want %q", pt, ptAADSecret)
	}
	if _, err := oldSvc.DecryptSecretWithAAD(gotAAD.EncryptedValue, aadAAD); err == nil {
		t.Error("aad secret: old DEK still decrypts after rotation")
	}

	// secret_versions — legacy row, must now be AAD v2 and decrypt under the new key.
	var gotLegacy models.SecretVersion
	mustFirst(t, db, &gotLegacy, legacyVer.ID)
	var legacyMetaAfter enc.EncryptionMetadata
	if err := json.Unmarshal([]byte(gotLegacy.EncryptionMetadata), &legacyMetaAfter); err != nil {
		t.Fatalf("unmarshal upgraded legacy metadata: %v", err)
	}
	if legacyMetaAfter.AADVersion != "v2" {
		t.Errorf("legacy row not upgraded: AADVersion=%q want %q", legacyMetaAfter.AADVersion, "v2")
	}
	if pt, err := newSvc.DecryptSecretWithAAD(gotLegacy.EncryptedValue, legacyAAD); err != nil {
		t.Errorf("legacy secret: new DEK decrypt failed: %v", err)
	} else if string(pt) != ptLegacy {
		t.Errorf("legacy secret: got %q want %q", pt, ptLegacy)
	}
	if _, err := oldSvc.DecryptSecretWithAAD(gotLegacy.EncryptedValue, legacyAAD); err == nil {
		t.Error("legacy secret: old DEK still decrypts after rotation")
	}

	// auth tables — plain (no-AAD) re-encryption.
	checkAuthRow := func(name string, blob []byte, want string) {
		if pt, err := newSvc.DecryptSecret(blob); err != nil {
			t.Errorf("%s: new DEK decrypt failed: %v", name, err)
		} else if string(pt) != want {
			t.Errorf("%s: got %q want %q", name, pt, want)
		}
		if _, err := oldSvc.DecryptSecret(blob); err == nil {
			t.Errorf("%s: old DEK still decrypts after rotation", name)
		}
	}
	var gotSession models.Session
	mustFirst(t, db, &gotSession, session.ID)
	checkAuthRow("session", gotSession.EncryptedSessionToken, ptSession)

	var gotToken models.APIToken
	mustFirst(t, db, &gotToken, apiToken.ID)
	checkAuthRow("api_token", gotToken.EncryptedToken, ptAPIToken)

	var gotClient models.APIClient
	mustFirst(t, db, &gotClient, apiClient.ID)
	checkAuthRow("api_client", gotClient.EncryptedClientSecret, ptAPIClient)

	var gotReset models.PasswordReset
	mustFirst(t, db, &gotReset, passwordReset.ID)
	checkAuthRow("password_reset", gotReset.EncryptedToken, ptPasswordRst)

	// backup files deleted.
	if matches, _ := filepath.Glob(filepath.Join(workDir, "dek.key.backup.*")); len(matches) != 0 {
		t.Errorf("backup DEK files not deleted: %v", matches)
	}
	// pending file cleaned up.
	if _, err := os.Stat(filepath.Join(workDir, "dek.key.pending")); !os.IsNotExist(err) {
		t.Errorf("dek.key.pending was not cleaned up (stat err: %v)", err)
	}
}

// configureBackend points cfg at the chosen backend and returns a factory that
// opens a fresh *gorm.DB to it. For Postgres it provisions an isolated schema
// (dropped on cleanup) so the shared dev database is never mutated.
func configureBackend(t *testing.T, kind string, cfg *config.Config, workDir string) func() *gorm.DB {
	t.Helper()
	switch kind {
	case "postgres":
		base := os.Getenv("KEYORIX_TEST_PG_DSN")
		schema := fmt.Sprintf("rot_e2e_%d", os.Getpid())
		admin := openPostgres(t, base)
		mustExec(t, admin, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		mustExec(t, admin, "CREATE SCHEMA "+schema)
		closeGorm(admin)
		t.Cleanup(func() {
			admin := openPostgres(t, base)
			mustExec(t, admin, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
			closeGorm(admin)
		})
		dsn := base + " search_path=" + schema
		cfg.Storage.Type = "postgres"
		cfg.Storage.Database.DSN = dsn
		return func() *gorm.DB { return openPostgres(t, dsn) }
	default: // sqlite on-disk file
		dbPath := filepath.Join(workDir, "secrets.db")
		cfg.Storage.Type = "local"
		cfg.Storage.Database.Path = dbPath
		return func() *gorm.DB {
			db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			return db
		}
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func mustEncrypt(t *testing.T, svc *enc.Service, plaintext string) ([]byte, []byte) {
	t.Helper()
	val, meta, err := svc.EncryptSecret([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptSecret(%q): %v", plaintext, err)
	}
	return val, meta
}

func mustEncryptAAD(t *testing.T, svc *enc.Service, plaintext string, aad []byte) ([]byte, []byte) {
	t.Helper()
	val, meta, err := svc.EncryptSecretWithAAD([]byte(plaintext), aad)
	if err != nil {
		t.Fatalf("EncryptSecretWithAAD(%q): %v", plaintext, err)
	}
	return val, meta
}

func mustCreate(t *testing.T, db *gorm.DB, v interface{}) {
	t.Helper()
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("insert %T: %v", v, err)
	}
}

func mustFirst(t *testing.T, db *gorm.DB, dst interface{}, id uint) {
	t.Helper()
	if err := db.First(dst, id).Error; err != nil {
		t.Fatalf("fetch %T id=%d: %v", dst, id, err)
	}
}

func openPostgres(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	return db
}

func mustExec(t *testing.T, db *gorm.DB, sql string) {
	t.Helper()
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func closeGorm(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
