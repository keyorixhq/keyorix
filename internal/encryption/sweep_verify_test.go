package encryption

// sweep_verify_test.go — DEK-ROTATE-SAFETY-1 item 1: a DEK rotation whose
// sweep writes one undecryptable ciphertext must commit nothing and leave the
// old DEK able to decrypt every row.
//
// The fault is injected below the sweep, as a GORM update callback on the test
// database (a faulting wrapper around the sweep's row write): the sweep itself
// runs unmodified, so the test exercises the real production path and needs
// no seam in production code.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// rewrapFault is how the faulting wrapper damages one rewritten ciphertext.
type rewrapFault func(t *testing.T, serialized []byte) []byte

// flipCiphertextByte flips one byte of the sealed data (a torn or bit-flipped write).
func flipCiphertextByte(t *testing.T, serialized []byte) []byte {
	t.Helper()
	ed, err := DeserializeEncryptedData(serialized)
	if err != nil {
		t.Fatalf("faulting wrapper: deserialize: %v", err)
	}
	ed.Data[len(ed.Data)/2] ^= 0x01
	out, err := SerializeEncryptedData(ed)
	if err != nil {
		t.Fatalf("faulting wrapper: serialize: %v", err)
	}
	return out
}

// sealUnderForeignKey re-seals the value under a key that is neither the old
// nor the new DEK (a rewrap that used the wrong key).
func sealUnderForeignKey(t *testing.T, serialized []byte) []byte {
	t.Helper()
	ed, err := DeserializeEncryptedData(serialized)
	if err != nil {
		t.Fatalf("faulting wrapper: deserialize: %v", err)
	}
	k, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := NewEncryptionService(k)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := foreign.EncryptWithAAD([]byte("not-the-row-value"), ed.Metadata.KeyVersion, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := SerializeEncryptedData(sealed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// installRewrapFault registers a GORM callback that applies fault to the
// sweep's write of column on the row of table with id target. Returns a
// counter of how many writes it damaged.
func installRewrapFault(t *testing.T, db *gorm.DB, table, column string, target uint, fault rewrapFault) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	name := fmt.Sprintf("test:rewrap-fault:%s", t.Name())
	err := db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		m, ok := tx.Statement.Dest.(map[string]any)
		if !ok {
			return
		}
		raw, ok := m[column].([]byte)
		if !ok {
			return
		}
		if !whereTargetsID(tx, target) {
			return
		}
		if table == "notification_channels" {
			tag, payload, err := NotificationChannelURLUnwrap(raw)
			if err != nil {
				t.Errorf("faulting wrapper: unwrap: %v", err)
				return
			}
			m[column] = NotificationChannelURLWrap(tag, fault(t, payload))
		} else {
			m[column] = fault(t, raw)
		}
		hits.Add(1)
	})
	if err != nil {
		t.Fatalf("register faulting wrapper: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove(name) })
	return &hits
}

// whereTargetsID reports whether the statement's WHERE is "id = target".
// The sweep's writes are tx.Model(...).Where("id = ?", id).Updates(map).
func whereTargetsID(tx *gorm.DB, target uint) bool {
	c, ok := tx.Statement.Clauses["WHERE"]
	if !ok {
		return false
	}
	where, ok := c.Expression.(clause.Where)
	if !ok {
		return false
	}
	for _, e := range where.Exprs {
		expr, ok := e.(clause.Expr)
		if !ok || expr.SQL != "id = ?" || len(expr.Vars) != 1 {
			continue
		}
		if id, ok := expr.Vars[0].(uint); ok && id == target {
			return true
		}
	}
	return false
}

// verifyFixture is a database with encrypted rows in several swept tables.
type verifyFixture struct {
	db         *gorm.DB
	svc        *Service
	dir        string
	passphrase string
	versionIDs []uint
	mfaID      uint
	channelID  uint
	snapshot   map[string][]byte
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	f := &verifyFixture{db: newTestDB(t), passphrase: "pre-commit-verify"}
	f.svc, f.dir = newTestService(t, f.passphrase)
	t.Cleanup(func() { f.svc.Shutdown() })
	const projectID = uint(4)
	nodeID := seedSecretNode(t, f.db, projectID)
	for v := 1; v <= 5; v++ {
		f.versionIDs = append(f.versionIDs, seedSecretVersion(t, f.db, f.svc, nodeID, projectID, v, fmt.Sprintf("value-%d", v)))
	}
	enc, meta, err := f.svc.EncryptSecretWithAAD([]byte("TOTP-SEED"), MFASecretAAD(7))
	if err != nil {
		t.Fatal(err)
	}
	mfa := &models.MFASecret{UserID: 7, SecretEnc: enc, SecretMeta: meta}
	if err := f.db.Create(mfa).Error; err != nil {
		t.Fatal(err)
	}
	f.mfaID = mfa.ID
	ch := &models.NotificationChannel{Name: "ops", Type: "webhook"}
	if err := f.db.Create(ch).Error; err != nil {
		t.Fatal(err)
	}
	urlEnc, urlMeta, err := f.svc.EncryptSecretWithAAD([]byte("https://hooks.example.invalid/x"), NotificationChannelURLAAD(ch.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(ch).Updates(map[string]any{
		"url_enc": NotificationChannelURLWrap(NotificationChannelURLTagEncrypted, urlEnc), "url_meta": urlMeta,
	}).Error; err != nil {
		t.Fatal(err)
	}
	f.channelID = ch.ID
	f.snapshot = f.read(t)
	return f
}

// read returns every encrypted column of the fixture's rows.
func (f *verifyFixture) read(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, id := range f.versionIDs {
		var v models.SecretVersion
		if err := f.db.First(&v, id).Error; err != nil {
			t.Fatal(err)
		}
		out[fmt.Sprintf("secret_versions/%d", id)] = v.EncryptedValue
	}
	var m models.MFASecret
	if err := f.db.First(&m, f.mfaID).Error; err != nil {
		t.Fatal(err)
	}
	out["mfa_secrets"] = m.SecretEnc
	var c models.NotificationChannel
	if err := f.db.First(&c, f.channelID).Error; err != nil {
		t.Fatal(err)
	}
	out["notification_channels"] = c.URLEnc
	return out
}

// assertNothingCommitted checks the rotation left the database and the key
// directory exactly as they were, and that the old DEK, loaded fresh from disk,
// still decrypts every row.
func (f *verifyFixture) assertNothingCommitted(t *testing.T, oldDEK []byte) {
	t.Helper()
	after := f.read(t)
	for k, before := range f.snapshot {
		if !bytes.Equal(before, after[k]) {
			t.Errorf("%s was rewritten although the rotation failed its pre-commit check", k)
		}
	}
	var markers int64
	f.db.Model(&models.SystemMetadata{}).Where("key = ?", dekRotationPromotePendingKey).Count(&markers)
	if markers != 0 {
		t.Errorf("the rotation's redo marker was committed")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "dek.key.pending")); !os.IsNotExist(err) {
		t.Errorf("dek.key.pending must be removed after a refused rotation (stat err %v)", err)
	}
	if got := captureCurrentDEK(t, f.svc); !bytes.Equal(got, oldDEK) {
		t.Errorf("the in-memory DEK changed although the rotation failed")
	}

	fresh := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, f.dir)
	if err := fresh.RecoverInterruptedRotation(f.db); err != nil {
		t.Fatalf("RecoverInterruptedRotation: %v", err)
	}
	if err := fresh.Initialize(f.passphrase); err != nil {
		t.Fatalf("Initialize from disk: %v", err)
	}
	defer fresh.Shutdown()
	if got := captureCurrentDEK(t, fresh); !bytes.Equal(got, oldDEK) {
		t.Fatalf("the DEK on disk is not the old DEK after a refused rotation")
	}
	for i, id := range f.versionIDs {
		var v models.SecretVersion
		if err := f.db.First(&v, id).Error; err != nil {
			t.Fatal(err)
		}
		var n models.SecretNode
		if err := f.db.First(&n, v.SecretNodeID).Error; err != nil {
			t.Fatal(err)
		}
		pt, err := fresh.DecryptSecretWithAAD(v.EncryptedValue, SecretAAD(v.SecretNodeID, n.ProjectID, v.VersionNumber))
		if want := fmt.Sprintf("value-%d", i+1); err != nil || string(pt) != want {
			t.Errorf("DATA LOSS: secret_versions id=%d does not decrypt under the old DEK (err %v)", id, err)
		}
	}
	var m models.MFASecret
	if err := f.db.First(&m, f.mfaID).Error; err != nil {
		t.Fatal(err)
	}
	if pt, err := fresh.DecryptSecretWithAAD(m.SecretEnc, MFASecretAAD(7)); err != nil || string(pt) != "TOTP-SEED" {
		t.Errorf("DATA LOSS: mfa_secrets id=%d does not decrypt under the old DEK (err %v)", m.ID, err)
	}
}

// TestRotateDEKWithSweep_PreCommitVerify_UndecryptableRewrapCommitsNothing
// injects, per table and fault shape, one rewritten ciphertext the new DEK
// cannot open. Before the pre-commit check the sweep committed it, the old DEK
// was retired, and that row was lost.
func TestRotateDEKWithSweep_PreCommitVerify_UndecryptableRewrapCommitsNothing(t *testing.T) {
	cases := []struct {
		name   string
		table  string
		column string
		target func(f *verifyFixture) uint
		fault  rewrapFault
		wantID string
	}{
		{"secret_version/bit-flip", "secret_versions", "encrypted_value", func(f *verifyFixture) uint { return f.versionIDs[2] }, flipCiphertextByte, "secret_versions id=%d"},
		{"secret_version/foreign-key", "secret_versions", "encrypted_value", func(f *verifyFixture) uint { return f.versionIDs[4] }, sealUnderForeignKey, "secret_versions id=%d"},
		{"mfa_secret/bit-flip", "mfa_secrets", "secret_enc", func(f *verifyFixture) uint { return f.mfaID }, flipCiphertextByte, "mfa_secrets id=%d"},
		{"notification_channel/bit-flip", "notification_channels", "url_enc", func(f *verifyFixture) uint { return f.channelID }, flipCiphertextByte, "notification_channels id=%d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerifyFixture(t)
			oldDEK := captureCurrentDEK(t, f.svc)
			target := tc.target(f)
			hits := installRewrapFault(t, f.db, tc.table, tc.column, target, tc.fault)

			_, err := f.svc.RotateDEKWithSweep(f.passphrase, f.db)
			if hits.Load() == 0 {
				t.Fatalf("the faulting wrapper never saw the sweep's write of %s id=%d (fixture broken)", tc.table, target)
			}
			if err == nil {
				t.Fatalf("DATA LOSS: the rotation committed although %s id=%d does not decrypt under the new DEK", tc.table, target)
			}
			if !strings.Contains(err.Error(), "pre-commit verification") {
				t.Errorf("want the pre-commit verification refusal, got %v", err)
			}
			if want := fmt.Sprintf(tc.wantID, target); !strings.Contains(err.Error(), want) {
				t.Errorf("the error must name the failing row (%q): %v", want, err)
			}
			for _, secret := range []string{"value-", "TOTP-SEED", "hooks.example"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error leaks a plaintext value (%q): %v", secret, err)
				}
			}
			f.assertNothingCommitted(t, oldDEK)
		})
	}
}
