package admin

// DEK-ROTATE-SAFETY-1 item 2 (DEK-ROTATION-CROSS-HOST): two replicas on one
// PostgreSQL database, each with its own copy of the key directory (dek.lock is
// per host, so it does not see the other). Replica B is a live server: it holds
// the shared presence lock and runs the DEK epoch guard. It encrypts a value
// while its DEK is still the database's (allowed), stalls, and INSERTs it after
// replica A's `admin encryption rotate --force` committed its sweep. That row
// is under the old DEK, and the key set A distributes cannot decrypt it.
//
// The epoch (#3337) fences B's NEW encryptions but cannot see a value encrypted
// before the fence whose INSERT lands after the sweep's table lock. Only the
// presence lock keeps that from happening, so `rotate` must not run without it
// on PostgreSQL, --force or not. Gated on KEYORIX_TEST_PG_DSN.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAdminEncryptionRotate_Postgres_ForceNextToLiveReplica_NoStaleDEKRow(t *testing.T) {
	const pass = "test-passphrase-1234"
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", pass)
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))

	// Replica A's host: the admin command runs here (flock key_dir_lock, the default).
	dirA := t.TempDir()
	chdirTest(t, dirA)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	initSvc := encryption.NewService(encCfg, dirA)
	require.NoError(t, initSvc.Initialize(pass))
	initSvc.Shutdown()
	configPathFlag = filepath.Join(dirA, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPathFlag, []byte(fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: kek.salt
`, dsn)), 0o600))
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	// Replica B's host: a copy of the same key set.
	dirB := t.TempDir()
	entries, err := os.ReadDir(dirA)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".lock" || e.Name() == "keyorix.yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dirA, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dirB, e.Name()), b, 0o600))
	}
	db := pgAdminRawOpen(t, dsn)
	replicaB := encryption.NewService(encCfg, dirB)
	require.NoError(t, replicaB.Initialize(pass))
	require.NoError(t, replicaB.StartDEKEpochGuard(pgAdminRawOpen(t, dsn), nil))
	defer replicaB.Shutdown()
	presence, err := serverguard.AcquirePresence(cfg)
	require.NoError(t, err)
	defer presence.Release() //nolint:errcheck

	project := models.Project{Name: "cross-host"}
	require.NoError(t, db.Create(&project).Error)
	node := models.SecretNode{ProjectID: project.ID, Name: "stalled", IsSecret: true}
	require.NoError(t, db.Create(&node).Error)
	aad := encryption.SecretAAD(node.ID, node.ProjectID, 1)
	// B encrypts while its DEK is the database's current one...
	enc, meta, err := replicaB.EncryptSecretWithAAD([]byte("written-by-replica-b"), aad)
	require.NoError(t, err)

	forceFlag, encRotateConfirm = true, true
	defer func() { forceFlag, encRotateConfirm, lockBypass = false, false, "" }()
	out, rotErr := captureStdout(t, func() error { return runEncRotate(nil, nil) })

	// ...and its INSERT lands after A's rotation.
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error)

	// The key set the operator distributes is A's.
	current := encryption.NewService(encCfg, dirA)
	require.NoError(t, current.Initialize(pass))
	defer current.Shutdown()
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", node.ID).First(&v).Error)
	if _, derr := current.DecryptSecretWithAAD(v.EncryptedValue, aad); derr != nil {
		t.Fatalf("DATA LOSS: replica B's version (id=%d) committed after the rotation is under the retired DEK (rotate err=%v): %v\n%s", v.ID, rotErr, derr, out)
	}
	require.Error(t, rotErr, "rotate --force ran next to a live replica:\n%s", out)
	require.Contains(t, rotErr.Error(), "--force cannot override it")
}
