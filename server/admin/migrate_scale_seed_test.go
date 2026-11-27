// migrate_scale_seed_test.go (MIGRATE-SCALE-NOV-1, #3462): the scale generator
// for the in-process migrate/restore scale tests (migrate_scale_test.go).
//
// scripts/migrate/scalegen fills a database for the real-binary rig
// (scale-check.sh) with random ciphertext, because that rig measures row volume.
// This helper is the in-process counterpart: every secret version is encrypted
// with the instance's own DEK, so a test can also decrypt every version on the
// far side of a move and compare it with what was written. It seeds projects with
// environments, users, a role granted to every user, secrets with versions,
// shares, secret access-log rows and a chained audit log.
//
// Sizes come from the environment so a laptop can run a larger set than CI:
//
//	KEYORIX_MIGSCALE_SECRETS   secrets at multiplier 1       (default 60)
//	KEYORIX_MIGSCALE_VERSIONS  versions per secret           (default 3)
//	KEYORIX_MIGSCALE_AUDIT     audit events at multiplier 1  (default 1200)
//
// users, shares and access-log rows follow the secret count. The defaults finish
// in seconds; the memory tests run each leg at multiplier 1 and 4.
//
// Not t.Parallel(): see backup_restore_integration_test.go.
package admin

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	scaleSeedPassphrase = "test-passphrase-1234"
	scaleSeedBatch      = 500
	scaleGenesisHash    = "0000000000000000000000000000000000000000000000000000000000000000"
)

// scaleSpec is the row volume of one seeded instance.
type scaleSpec struct {
	Projects, Users, Secrets, Versions, Shares, AccessLogs, Audit int
}

// scaleSpecFromEnv reads the size knobs and multiplies the row counts by mult.
func scaleSpecFromEnv(t *testing.T, mult int) scaleSpec {
	t.Helper()
	secrets := scaleEnvInt(t, "KEYORIX_MIGSCALE_SECRETS", 60) * mult
	return scaleSpec{
		Projects:   3,
		Users:      max(secrets/10, 4),
		Secrets:    secrets,
		Versions:   scaleEnvInt(t, "KEYORIX_MIGSCALE_VERSIONS", 3),
		Shares:     secrets / 2,
		AccessLogs: secrets * 2,
		Audit:      scaleEnvInt(t, "KEYORIX_MIGSCALE_AUDIT", 1200) * mult,
	}
}

func scaleEnvInt(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	require.NoError(t, err, "%s must be a positive integer", key)
	require.Positive(t, n, "%s must be a positive integer", key)
	return n
}

// scaleContentModels are the tables a move must carry over with equal row counts.
func scaleContentModels() map[string]any {
	return map[string]any{
		"projects":           &models.Project{},
		"environments":       &models.Environment{},
		"users":              &models.User{},
		"roles":              &models.Role{},
		"user_roles":         &models.UserRole{},
		"secret_nodes":       &models.SecretNode{},
		"secret_versions":    &models.SecretVersion{},
		"share_records":      &models.ShareRecord{},
		"secret_access_logs": &models.SecretAccessLog{},
		"audit_events":       &models.AuditEvent{},
	}
}

// scaleCounts returns the row count of every content table (soft-deleted rows included).
func scaleCounts(t *testing.T, db *gorm.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for name, model := range scaleContentModels() {
		var n int64
		require.NoError(t, db.Unscoped().Model(model).Count(&n).Error, "count %s", name)
		out[name] = n
	}
	return out
}

// scalePlaintext is what version v of secret node id holds: derivable from the
// row alone, so decryptAll needs no side table however many rows there are.
func scalePlaintext(nodeID uint, version int) string {
	return fmt.Sprintf("scale-pt-%d-v%d", nodeID, version)
}

// seedScale fills db (already migrated, key files already initialised and
// opened as svc) with the rows spec asks for, in batches of scaleSeedBatch.
func seedScale(t *testing.T, db *gorm.DB, svc *encryption.Service, spec scaleSpec) {
	t.Helper()
	create := func(rows any) { require.NoError(t, db.Create(rows).Error) }

	projectIDs := make([]uint, spec.Projects)
	envIDs := make([]uint, spec.Projects)
	for i := range projectIDs {
		p := &models.Project{Name: fmt.Sprintf("scale-proj-%d", i)}
		create(p)
		e := &models.Environment{ProjectID: p.ID, Name: "prod"}
		create(e)
		projectIDs[i], envIDs[i] = p.ID, e.ID
	}

	role := &models.Role{Name: "scale-role", NameFolded: "scale-role", Description: "scale test role"}
	create(role)

	users := make([]models.User, spec.Users)
	for i := range users {
		n := fmt.Sprintf("scale-user-%d", i)
		users[i] = models.User{Username: n, UsernameFolded: n, Email: n + "@example.invalid", EmailFolded: n + "@example.invalid",
			DisplayName: n, IsActive: true}
	}
	require.NoError(t, db.CreateInBatches(users, scaleSeedBatch).Error)
	grants := make([]models.UserRole, len(users))
	for i := range users {
		grants[i] = models.UserRole{UserID: users[i].ID, RoleID: role.ID, ProjectID: projectIDs[i%len(projectIDs)]}
	}
	require.NoError(t, db.CreateInBatches(grants, scaleSeedBatch).Error)

	nodeIDs := make([]uint, 0, spec.Secrets)
	now := time.Now().UTC()
	for from := 0; from < spec.Secrets; from += scaleSeedBatch {
		to := min(from+scaleSeedBatch, spec.Secrets)
		nodes := make([]models.SecretNode, 0, to-from)
		for i := from; i < to; i++ {
			nodes = append(nodes, models.SecretNode{ProjectID: projectIDs[i%len(projectIDs)], EnvironmentID: envIDs[i%len(projectIDs)],
				Name: fmt.Sprintf("scale-secret-%d", i), IsSecret: true, Type: "password", Status: "active", CreatedBy: "scale-seed"})
		}
		require.NoError(t, db.Create(&nodes).Error)
		vers := make([]models.SecretVersion, 0, len(nodes)*spec.Versions)
		for _, nd := range nodes {
			nodeIDs = append(nodeIDs, nd.ID)
			for v := 1; v <= spec.Versions; v++ {
				ct, _, err := svc.EncryptSecret([]byte(scalePlaintext(nd.ID, v)))
				require.NoError(t, err)
				vers = append(vers, models.SecretVersion{SecretNodeID: nd.ID, VersionNumber: v, EncryptedValue: ct, CreatedAt: now})
			}
		}
		require.NoError(t, db.CreateInBatches(vers, scaleSeedBatch).Error)
	}

	shares := make([]models.ShareRecord, spec.Shares)
	for i := range shares {
		shares[i] = models.ShareRecord{SecretID: nodeIDs[i%len(nodeIDs)], OwnerID: users[i%len(users)].ID,
			RecipientID: users[(i+1)%len(users)].ID, Permission: "read"}
	}
	require.NoError(t, db.CreateInBatches(shares, scaleSeedBatch).Error)

	base := now.Add(-time.Duration(spec.AccessLogs) * time.Second)
	logs := make([]models.SecretAccessLog, spec.AccessLogs)
	for i := range logs {
		logs[i] = models.SecretAccessLog{SecretNodeID: nodeIDs[i%len(nodeIDs)], SecretVersionID: 1, AccessedBy: "scale-seed",
			AccessTime: base.Add(time.Duration(i) * time.Second), Action: "read", IPAddress: "10.0.0.1", UserAgent: "scale-seed"}
	}
	require.NoError(t, db.CreateInBatches(logs, scaleSeedBatch).Error)

	seedScaleAudit(t, db, spec.Audit, projectIDs, users, nodeIDs)
}

// seedScaleAudit links n events onto the chain head in id order, using the
// store's own hash function, so verify-audit accepts them as it accepts rows
// the server wrote.
func seedScaleAudit(t *testing.T, db *gorm.DB, n int, projectIDs []uint, users []models.User, nodeIDs []uint) {
	t.Helper()
	prev := scaleGenesisHash
	var head models.AuditEvent
	require.NoError(t, db.Where("entry_hash != ''").Order("id DESC").Limit(1).Find(&head).Error)
	if head.ID != 0 {
		prev = head.EntryHash
	}
	types := []string{"secret.read", "secret.updated", "auth.login", "share.created", "rbac.role_assigned", "project.created"}
	ok := true
	base := time.Now().UTC().Add(-time.Duration(n+60) * time.Second).Truncate(time.Microsecond)
	for from := 0; from < n; from += scaleSeedBatch {
		to := min(from+scaleSeedBatch, n)
		rows := make([]models.AuditEvent, 0, to-from)
		for i := from; i < to; i++ {
			pid, uid := projectIDs[i%len(projectIDs)], users[i%len(users)].ID
			ev := models.AuditEvent{EventType: types[i%len(types)], IPAddress: "10.0.0.1", Description: fmt.Sprintf("scale event %d", i),
				Success: &ok, EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user", ProjectID: &pid, UserID: &uid}
			if i%len(types) < 2 {
				nid := nodeIDs[i%len(nodeIDs)]
				ev.SecretNodeID = &nid
			}
			ev.PrevHash = prev
			ev.EntryHash = store.ComputeAuditEntryHash(&ev, prev)
			prev = ev.EntryHash
			rows = append(rows, ev)
		}
		require.NoError(t, db.Create(rows).Error)
	}
}

// decryptAllScale decrypts every secret version in db with svc and compares it
// with scalePlaintext. It pages through the table, so the check itself holds one
// batch at a time. Returns the number of versions checked.
func decryptAllScale(t *testing.T, db *gorm.DB, svc *encryption.Service) int64 {
	t.Helper()
	var checked int64
	var batch []models.SecretVersion
	res := db.Unscoped().Order("id").FindInBatches(&batch, scaleSeedBatch, func(_ *gorm.DB, _ int) error {
		for _, v := range batch {
			pt, err := svc.DecryptSecret(v.EncryptedValue)
			if err != nil {
				return fmt.Errorf("secret node %d version %d: %w", v.SecretNodeID, v.VersionNumber, err)
			}
			if got, want := string(pt), scalePlaintext(v.SecretNodeID, v.VersionNumber); got != want {
				return fmt.Errorf("secret node %d version %d decrypts to %q, want %q", v.SecretNodeID, v.VersionNumber, got, want)
			}
			checked++
		}
		return nil
	})
	require.NoError(t, res.Error, "decrypt-all")
	return checked
}

// verifyAuditValid runs `admin verify-audit` against the config at cfgPath and
// requires a VALID verdict over at least wantChained chained events.
func verifyAuditValid(t *testing.T, cfgPath string, wantChained int64) {
	t.Helper()
	resetVerifyAuditAndExportFlags(t)
	configPathFlag = cfgPath
	res, err := runVerifyAuditCapturingJSON(t)
	require.NoError(t, err, "verify-audit")
	require.Equal(t, auditverify.VerdictValid, res.Verdict, "verify-audit verdict: %s", res.Reason)
	require.GreaterOrEqual(t, res.ChainedEvents, wantChained)
}

// newSQLiteScaleConfig writes a local/SQLite config for dir and loads it.
func newSQLiteScaleConfig(t *testing.T, dir string) (string, *config.Config) {
	t.Helper()
	cfgPath := writeBackupRestoreTestConfig(t, dir, dir+"/secrets.db")
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	return cfgPath, cfg
}

// TestScaleSeed_SQLite_SeedsEverythingChainVerifiesAndDecrypts is the generator's
// own check: each table holds exactly the rows spec asked for, verify-audit accepts
// the chain it built, and every version decrypts to the value written.
func TestScaleSeed_SQLite_SeedsEverythingChainVerifiesAndDecrypts(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", scaleSeedPassphrase)

	dir := t.TempDir()
	chdirTest(t, dir)
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	require.NoError(t, svc.Initialize(scaleSeedPassphrase))
	cfgPath, cfg := newSQLiteScaleConfig(t, dir)
	st, err := createStorageClosedAtCleanup(t, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { closeTestStorage(st) })

	spec := scaleSpecFromEnv(t, 1)
	db, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	seedScale(t, db, svc, spec)

	counts := scaleCounts(t, db)
	require.EqualValues(t, spec.Projects, counts["projects"])
	require.EqualValues(t, spec.Users, counts["users"])
	require.EqualValues(t, spec.Users, counts["user_roles"])
	require.EqualValues(t, spec.Secrets, counts["secret_nodes"])
	require.EqualValues(t, spec.Secrets*spec.Versions, counts["secret_versions"])
	require.EqualValues(t, spec.Shares, counts["share_records"])
	require.EqualValues(t, spec.AccessLogs, counts["secret_access_logs"])
	require.GreaterOrEqual(t, counts["audit_events"], int64(spec.Audit))

	require.EqualValues(t, spec.Secrets*spec.Versions, decryptAllScale(t, db, svc))
	closeGormDB(db)
	verifyAuditValid(t, cfgPath, int64(spec.Audit))
}
