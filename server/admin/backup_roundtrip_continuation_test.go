// backup_roundtrip_continuation_test.go implements oracle 5 (CONTINUATION), the
// property the committed fuzzer documents as not-yet-implemented. Oracles 1/4
// compare the SAME rows before/after a restore (restore preserves primary keys
// and timestamps, so a byte/instant comparison is sound). Continuation asks a
// stronger question: if restore(backup(S)) is truly logically equal to S, then
// applying the SAME further operations to S and to the restored store R must
// assign the SAME new identities and produce the same new decryptable state.
//
// This specifically exercises SEQUENCE / auto-increment-state preservation
// across a restore (Postgres: resyncPostgresSequences; SQLite: explicit-rowid
// inserts advancing the autoincrement) end-to-end from the application layer: a
// restore that reset a sequence would hand out a COLLIDING or divergent id for
// the first post-restore insert, which this test's id-equality assertions catch.
//
// It does NOT compare full post-continuation backups byte-for-byte: rows created
// independently on S and on R carry independent wall-clock created_at/updated_at
// instants, which assertLogicalEqual compares by parsed instant and would flag
// as a (spurious) diff. Continuation here is therefore asserted at the level
// that is backend-truthful and timestamp-free: identical assigned identities and
// identical decryptable plaintext for the follow-up operations.
package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// wiredCore opens an encryption service over dir and a core over cfgPath's store,
// returning the core and a gorm handle. passphrase unwraps the key files.
func wiredCore(t *testing.T, dir, cfgPath, passphrase string) (*core.KeyorixCore, *encryption.Service, *gorm.DB) {
	t.Helper()
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	enc := encryption.NewService(encCfg, dir)
	require.NoError(t, enc.Initialize(passphrase))
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	store, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	c := core.NewKeyorixCore(store)
	c.SetSecretValueEncryptor(enc)
	require.True(t, c.SecretValueEncryptionActive())
	return c, enc, gdb
}

// contCreateProjectAndSecret applies the identical follow-up op to a store: create
// a project by the given name (auto-seeds environments), then a secret with the
// given plaintext in its first environment. Returns the assigned (projectID,
// secretNodeID). Used to drive S and R identically.
func contCreateProjectAndSecret(t *testing.T, c *core.KeyorixCore, projName, secName string, pt []byte) (uint, uint) {
	t.Helper()
	ctx := context.Background()
	p, err := c.CreateProject(ctx, projName, "cont")
	require.NoError(t, err)
	envs, err := c.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	node, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: secName, Value: pt, ProjectID: p.ID, EnvironmentID: envs[0].ID,
		Type: "password", CreatedBy: "cont",
	})
	require.NoError(t, err)
	return p.ID, node.ID
}

func TestBackupRoundtripContinuation(t *testing.T) {
	backends := []string{"sqlite"}
	if os.Getenv("KEYORIX_TEST_PG_DSN") != "" {
		backends = append(backends, "postgres")
	}
	for _, backend := range backends {
		t.Run(backend, func(t *testing.T) { runContinuation(t, backend) })
	}
}

func runContinuation(t *testing.T, backend string) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	var pgBaseDSN string
	if backend == "postgres" {
		pgBaseDSN = bkPgBaseDSN(t)
	}

	// --- Source S: a small seeded, encrypted store. ---
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	encS := encryption.NewService(encCfg, srcDir)
	require.NoError(t, encS.Initialize(roundTripPassphrase))
	cfgS := bkConfigureBackend(t, backend, srcDir, pgBaseDSN)
	configPathFlag = cfgS
	cfg, err := loadConfig()
	require.NoError(t, err)
	storeS, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	gdbS, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	coreS := core.NewKeyorixCore(storeS)
	coreS.SetSecretValueEncryptor(encS)
	require.True(t, coreS.SecretValueEncryptionActive())

	actor := &models.User{Username: "cont-actor", UsernameFolded: "cont-actor"}
	require.NoError(t, gdbS.Create(actor).Error)
	// Seed one project + one secret so the id sequences are non-trivial.
	contCreateProjectAndSecret(t, coreS, "seed-proj", "seed-secret", []byte("seed-pt"))

	// --- Backup S, restore into R. ---
	archive := filepath.Join(t.TempDir(), "cont.tar.gz")
	_, _, _, err = backupTables(t, archive)
	require.NoError(t, err, "[%s] backup S", backend)

	dstDir, restoreOut, rerr := restoreInto(t, backend, pgBaseDSN, archive)
	require.NoError(t, rerr, "[%s] restore: %s", backend, restoreOut)
	require.Contains(t, restoreOut, "verify-audit on the restored database: VALID")
	cfgR := configPathFlag // restoreInto set this to R's config and chdir'd into dstDir

	// Wire a fresh core over the restored store R (same DEK: restore copied dek.key).
	coreR, _, _ := wiredCore(t, dstDir, cfgR, roundTripPassphrase)

	// --- Continuation: apply the IDENTICAL follow-up op to S and to R. ---
	const pjName, scName = "cont-proj", "cont-secret"
	contPT := []byte("continuation-plaintext")
	pidS, nidS := contCreateProjectAndSecret(t, coreS, pjName, scName, contPT)
	pidR, nidR := contCreateProjectAndSecret(t, coreR, pjName, scName, contPT)

	// Oracle 5: a restored store continues identically -- same assigned identities.
	require.Equal(t, pidS, pidR,
		"[%s] continuation: restored store assigned a DIFFERENT project id (sequence not preserved by restore)", backend)
	require.Equal(t, nidS, nidR,
		"[%s] continuation: restored store assigned a DIFFERENT secret id", backend)

	// Oracle 2 (continuation): the follow-up secret decrypts to its plaintext on R.
	var rowR models.SecretVersion
	require.NoError(t, (func() error {
		g, derr := storage.OpenGormDB(mustLoadCfg(t, cfgR))
		if derr != nil {
			return derr
		}
		return g.Where("secret_node_id = ? AND version_number = ?", nidR, 1).First(&rowR).Error
	})(), "[%s] read restored continuation version", backend)
	encR2 := encryption.NewService(encCfg, dstDir)
	require.NoError(t, encR2.Initialize(roundTripPassphrase))
	got, derr := encR2.DecryptSecretWithAAD(rowR.EncryptedValue, encryption.SecretAAD(nidR, pidR, 1))
	require.NoError(t, derr, "[%s] continuation secret must decrypt on R", backend)
	require.True(t, bytesEqualConst(got, contPT), "[%s] continuation plaintext mismatch on R", backend)
}

func mustLoadCfg(t *testing.T, cfgPath string) *config.Config {
	t.Helper()
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	return cfg
}
