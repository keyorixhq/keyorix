// kek_audit_transition_test.go — rotate-kek and migrate-provider carry the
// audit verification state over to the new checkpoint key
// (docs/design-audit-key-transition.md, #3642). Driven through the real
// commands: after an honest key change the next server process on the new key
// reads the incremental status and the chain walk VALID, and the offline
// verifier with the new checkpoint key reads VALID, also on an install that
// has had a retention purge (RECOVERY-OPTIONS-1 F2).
package encryptionops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditServer is one server process over the test database: storage from the
// production factory, a core keyed with the key svc derives, wired the way
// server/wire_encryption.go wires it (minus the completion call, which the
// commands now run themselves).
type auditServer struct {
	t  *testing.T
	st corestorage.Storage
	c  *core.KeyorixCore
	// key is the audit-checkpoint key the process runs on.
	key []byte
}

func startAuditServer(t *testing.T, cfg *config.Config, enc *config.EncryptionConfig, passphrase string) *auditServer {
	t.Helper()
	baseDir, _ := os.Getwd()
	svc := encryption.NewService(enc, baseDir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("svc.Initialize: %v", err)
	}
	key, kid, ok := svc.AuditCheckpointKey()
	svc.Shutdown() // the commands refuse to run while a process holds the key lock
	if !ok {
		t.Fatal("no audit checkpoint key")
	}
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}
	c := core.NewKeyorixCore(st)
	c.SetAuditCheckpointKey(key, kid)
	c.SetAuditIncrementalVerification(24*time.Hour, 1)
	c.SeedAuditWatermark(context.Background())
	return &auditServer{t: t, st: st, c: c, key: key}
}

// logEvents appends n chained events, age before now.
func (s *auditServer) logEvents(n int, age time.Duration) {
	s.t.Helper()
	base := time.Now().UTC().Add(-age).Truncate(time.Second)
	ok := true
	for i := range n {
		if err := s.st.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType: "secret.read", Description: fmt.Sprintf("event %d", i), Success: &ok,
			EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}); err != nil {
			s.t.Fatalf("LogAuditEvent: %v", err)
		}
	}
}

// settle runs verification ticks until the incremental status reads valid (or
// gives up) and returns the last report.
func (s *auditServer) settle() *core.AuditVerifyReport {
	s.t.Helper()
	ctx := context.Background()
	var r *core.AuditVerifyReport
	for range 5 {
		if _, err := s.c.RunAuditVerificationTick(ctx); err != nil {
			s.t.Logf("tick: %v", err)
		}
		var err error
		if r, err = s.c.VerifyAuditChainIncremental(ctx); err != nil {
			s.t.Fatalf("VerifyAuditChainIncremental: %v", err)
		}
		if r.Status == core.AuditVerifyStatusValid {
			break
		}
		s.logEvents(1, 0)
	}
	return r
}

// assertValid: the incremental status, the full walk and the offline verifier
// with this process's key all read valid.
func (s *auditServer) assertValid(cfg *config.Config, what string) {
	s.t.Helper()
	if r := s.settle(); r.Status != core.AuditVerifyStatusValid {
		s.t.Fatalf("%s: incremental status %s, want valid: %s %s", what, r.Status, r.Reason, r.NotProvenReason)
	}
	v, err := s.c.VerifyAuditChain(context.Background())
	if err != nil {
		s.t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !v.Valid {
		s.t.Fatalf("%s: online chain walk broken: %s", what, v.Reason)
	}
	db, err := auditverify.OpenSQLiteReadOnly(cfg.Storage.Database.Path)
	if err != nil {
		s.t.Fatalf("OpenSQLiteReadOnly: %v", err)
	}
	defer func() { _ = db.Close() }()
	res, err := auditverify.Verify(context.Background(), db, auditverify.Options{CheckpointKey: s.key})
	if err != nil {
		s.t.Fatalf("auditverify.Verify: %v", err)
	}
	if res.Verdict != auditverify.VerdictValid {
		s.t.Fatalf("%s: offline verify-audit with the current checkpoint key reads %s: %s", what, res.Verdict, res.Reason)
	}
}

// certifiedInstall writes a chain, a checkpoint and a completed verification
// cycle under the baseline key; with purge, the oldest rows were removed by a
// sanctioned retention purge first.
func certifiedInstall(t *testing.T, cfg *config.Config, purge bool) {
	t.Helper()
	s := startAuditServer(t, cfg, &cfg.Storage.Encryption, testBaselinePassphrase)
	if purge {
		s.logEvents(5, 60*24*time.Hour)
	}
	s.logEvents(6, time.Hour)
	if _, _, err := s.c.WriteAuditCheckpoint(context.Background()); err != nil {
		t.Fatalf("WriteAuditCheckpoint: %v", err)
	}
	if purge {
		if _, err := s.c.PurgeAuditLogs(context.Background(), core.AuditLogRetentionConfig{RetentionDays: 30}); err != nil {
			t.Fatalf("PurgeAuditLogs: %v", err)
		}
	}
	s.assertValid(cfg, "before the key change")
}

func TestRotateKEK_CarriesAuditStateOver(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(fmt.Sprintf("purged=%v", purge), func(t *testing.T) {
			chdirTemp(t)
			cfg, _, _ := kekFixture(t)
			certifiedInstall(t, cfg, purge)

			setNewPassphraseEnv(t, testNewPassphrase)
			if out, err := captureOutput(t, func() error {
				return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
			}); err != nil {
				t.Fatalf("RotateKEKWithConfig: %v\n%s", err, out)
			}
			startAuditServer(t, cfg, &cfg.Storage.Encryption, testNewPassphrase).assertValid(cfg, "after rotate-kek")
		})
	}
}

func TestMigrateProvider_CarriesAuditStateOver(t *testing.T) {
	chdirTemp(t)
	cfg, _ := migrateFixture(t)
	certifiedInstall(t, cfg, true)

	keyFile := filepath.Join(t.TempDir(), "raw.key")
	raw := make([]byte, crypto.KEKSize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := MigrateOpts{ToType: "file", ToFilePath: keyFile}
	if out, err := captureOutput(t, func() error {
		return MigrateProviderWithConfig(cfg, opts, true, zeroPassSrc(), zeroPassSrc())
	}); err != nil {
		t.Fatalf("MigrateProviderWithConfig: %v\n%s", err, out)
	}
	tgt, err := TargetEncryptionConfig(&cfg.Storage.Encryption, opts)
	if err != nil {
		t.Fatal(err)
	}
	pass, err := TargetPassphrase(tgt.KeyProvider.Type, zeroPassSrc())
	if err != nil {
		t.Fatal(err)
	}
	startAuditServer(t, cfg, &tgt, pass).assertValid(cfg, "after migrate-provider")
}
