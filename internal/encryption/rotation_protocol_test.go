package encryption

// rotation_protocol_test.go — DEK-ROTATE-SAFETY-1 item 3: an admin binary whose
// DEK rotation protocol is older than the one the database records must not
// rotate it. The record is written with literal keys so this file also runs
// against binaries that predate the guard.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRotateDEKWithSweep_RefusesNewerRecordedRotationProtocol(t *testing.T) {
	for _, recorded := range []string{"999", "not-a-number"} {
		t.Run(recorded, func(t *testing.T) {
			db := newTestDB(t)
			svc, dir := newTestService(t, "rotation-protocol")
			defer svc.Shutdown()
			nodeID := seedSecretNode(t, db, 2)
			id := seedSecretVersion(t, db, svc, nodeID, 2, 1, "kept-under-the-old-dek")
			var before models.SecretVersion
			if err := db.First(&before, id).Error; err != nil {
				t.Fatal(err)
			}
			// A newer server recorded its rotation protocol.
			if err := db.Create(&models.SystemMetadata{Key: "dek.rotation_protocol", Value: recorded}).Error; err != nil {
				t.Fatal(err)
			}
			oldDEK := captureCurrentDEK(t, svc)

			_, err := svc.RotateDEKWithSweep("rotation-protocol", db)
			if err == nil {
				t.Fatalf("an admin binary older than the database's rotation protocol (%s) rotated it", recorded)
			}
			if !strings.Contains(err.Error(), "rotation protocol") {
				t.Errorf("the refusal must name the rotation protocol: %v", err)
			}
			var after models.SecretVersion
			if err := db.First(&after, id).Error; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before.EncryptedValue, after.EncryptedValue) {
				t.Error("a refused rotation rewrote a row")
			}
			if !bytes.Equal(captureCurrentDEK(t, svc), oldDEK) {
				t.Error("a refused rotation changed the DEK")
			}
			if _, err := os.Stat(filepath.Join(dir, "dek.key.pending")); !os.IsNotExist(err) {
				t.Errorf("a refused rotation left dek.key.pending (stat err %v)", err)
			}
		})
	}
}
