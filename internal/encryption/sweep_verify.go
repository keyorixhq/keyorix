// sweep_verify.go — pre-commit decrypt check of a DEK-sweep rotation
// (DEK-ROTATE-SAFETY-1 item 1).
//
// SweepAllTables re-encrypts every DEK-encrypted row inside the rotation's
// transaction. Once that transaction commits and the old DEK is retired, a
// single row the new DEK cannot open is lost for good. So before the commit
// (and so before the epoch moves to the new DEK and the pending DEK file is
// promoted), RotateDEKWithSweep runs two checks inside the same transaction:
//
//   - rewrapCanary, before the sweep writes anything: a sample of the newest
//     secret versions is decrypted with the old DEK, re-encrypted with the new
//     one and decrypted again, and the plaintexts are compared. A broken new
//     DEK fails here, before the write-locking sweep starts.
//   - verifySweptRows, after the sweep: a streamed pass (keyset pagination,
//     sweepBatchSize rows per query) over EVERY row of every swept table, read
//     back from the transaction, decrypted with the new DEK and the row's AAD.
//     Not a sample: one undecryptable version is data loss. The number of
//     ciphertexts it opened must also equal the number the sweep rewrote.
//
// Any failure returns an error wrapping ErrSweepVerification that names the
// table and row id (ids only, never a value). The caller rolls the
// transaction back, so nothing is committed and the old DEK stays active.
//
// Not covered: a rewrite that encrypts the WRONG plaintext under the new DEK
// still decrypts and passes verifySweptRows (only the canary sample compares
// plaintexts); the old ciphertext is gone from the transaction by then.
package encryption

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// ErrSweepVerification marks a DEK rotation refused by its pre-commit decrypt
// check: a rewritten row does not decrypt under the new DEK. Nothing was
// committed and the old DEK is still active.
var ErrSweepVerification = errors.New("pre-commit verification of the DEK rotation failed: nothing was committed and the old DEK stays active")

// rewrapCanarySize is how many of the newest secret versions rewrapCanary
// round-trips before the sweep starts.
const rewrapCanarySize = 16

// sweptCiphertext is one DEK-encrypted value read back for verification.
type sweptCiphertext struct {
	table string
	id    uint
	what  string // extra ids for the error message ("secret_node_id=3 version=2"); never a value
	enc   []byte
	aad   []byte // nil: the column is not AAD-bound (api_clients)
}

// sweptTableReader loads the batch of rows with id > after, in id order, and
// returns their ciphertexts plus the highest id seen (0 when the batch is empty).
type sweptTableReader func(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error)

// verifySweptRows decrypts every DEK-encrypted value in every swept table with
// newSvc and returns how many it opened. See the file comment.
func verifySweptRows(tx *gorm.DB, newSvc *EncryptionService) (int, error) {
	nodeProject := make(map[uint]uint)
	var nodes []models.SecretNode
	if err := tx.Unscoped().Select("id, project_id").Find(&nodes).Error; err != nil {
		return 0, fmt.Errorf("%w: read secret nodes: %v", ErrSweepVerification, err)
	}
	for _, n := range nodes {
		nodeProject[n.ID] = n.ProjectID
	}

	readers := []sweptTableReader{
		readSweptSecretVersions(nodeProject),
		readSweptAPITokens,
		readSweptAPIClients,
		readSweptPasswordResets,
		readSweptMFASecrets,
		readSweptDynamicSecretConfigs,
		readSweptDynamicSecretLeases,
		readSweptNotificationChannels,
	}
	total := 0
	for _, read := range readers {
		var after uint
		for {
			batch, last, err := read(tx, after, sweepBatchSize)
			if err != nil {
				return total, fmt.Errorf("%w: %v", ErrSweepVerification, err)
			}
			if last == 0 {
				break
			}
			for _, c := range batch {
				if err := openSwept(newSvc, c); err != nil {
					return total, err
				}
				total++
			}
			after = last
		}
	}
	return total, nil
}

// openSwept decrypts one read-back value with the new DEK.
func openSwept(newSvc *EncryptionService, c sweptCiphertext) error {
	fail := func(err error) error {
		where := fmt.Sprintf("%s id=%d", c.table, c.id)
		if c.what != "" {
			where += " (" + c.what + ")"
		}
		return fmt.Errorf("%w: %s does not decrypt under the new DEK: %v", ErrSweepVerification, where, err)
	}
	ed, err := DeserializeEncryptedData(c.enc)
	if err != nil {
		return fail(err)
	}
	var pt []byte
	if c.aad == nil {
		pt, err = newSvc.Decrypt(ed)
	} else {
		// The sweep re-encrypts every AAD-bound column with AAD; a row still
		// declaring none was not rewritten by it.
		if ed.Metadata.AADVersion == "" {
			return fail(errors.New("the row is not AAD-bound, so the sweep did not rewrite it"))
		}
		pt, err = newSvc.DecryptWithAAD(ed, c.aad)
	}
	if err != nil {
		return fail(err)
	}
	wipeBytes(pt)
	return nil
}

func readSweptSecretVersions(nodeProject map[uint]uint) sweptTableReader {
	return func(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
		var rows []models.SecretVersion
		if err := tx.Select("id, secret_node_id, version_number, encrypted_value").
			Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
			return nil, 0, fmt.Errorf("read secret_versions after id %d: %w", after, err)
		}
		out := make([]sweptCiphertext, 0, len(rows))
		var last uint
		for _, r := range rows {
			last = r.ID
			if len(r.EncryptedValue) == 0 {
				continue
			}
			projectID, ok := nodeProject[r.SecretNodeID]
			if !ok {
				return nil, 0, fmt.Errorf("no project found for secret_node_id=%d (secret_versions id=%d)", r.SecretNodeID, r.ID)
			}
			out = append(out, sweptCiphertext{
				table: "secret_versions", id: r.ID,
				what: fmt.Sprintf("secret_node_id=%d version=%d", r.SecretNodeID, r.VersionNumber),
				enc:  r.EncryptedValue, aad: SecretAAD(r.SecretNodeID, projectID, r.VersionNumber),
			})
		}
		return out, last, nil
	}
}

func readSweptAPITokens(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.APIToken
	if err := tx.Select("id, user_id, encrypted_token").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read api_tokens after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		if len(r.EncryptedToken) == 0 {
			continue
		}
		var uid uint
		if r.UserID != nil {
			uid = *r.UserID
		}
		out = append(out, sweptCiphertext{table: "api_tokens", id: r.ID, enc: r.EncryptedToken, aad: APITokenAAD(uid)})
	}
	return out, last, nil
}

func readSweptAPIClients(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.APIClient
	if err := tx.Select("id, encrypted_client_secret").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read api_clients after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		if len(r.EncryptedClientSecret) == 0 {
			continue
		}
		out = append(out, sweptCiphertext{table: "api_clients", id: r.ID, enc: r.EncryptedClientSecret})
	}
	return out, last, nil
}

func readSweptPasswordResets(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.PasswordReset
	if err := tx.Select("id, user_id, encrypted_token").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read password_resets after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		if len(r.EncryptedToken) == 0 {
			continue
		}
		out = append(out, sweptCiphertext{table: "password_resets", id: r.ID, enc: r.EncryptedToken, aad: PasswordResetTokenAAD(r.UserID)})
	}
	return out, last, nil
}

func readSweptMFASecrets(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.MFASecret
	if err := tx.Select("id, user_id, secret_enc").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read mfa_secrets after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		if len(r.SecretEnc) == 0 {
			continue
		}
		out = append(out, sweptCiphertext{table: "mfa_secrets", id: r.ID, enc: r.SecretEnc, aad: MFASecretAAD(r.UserID)})
	}
	return out, last, nil
}

func readSweptDynamicSecretConfigs(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.DynamicSecretConfig
	if err := tx.Select("id, project_id, environment_id, admin_dsn_enc").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read dynamic_secret_configs after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		if len(r.AdminDSNEnc) == 0 {
			continue
		}
		out = append(out, sweptCiphertext{table: "dynamic_secret_configs", id: r.ID, enc: r.AdminDSNEnc,
			aad: DynamicSecretConfigAAD(r.ID, r.ProjectID, r.EnvironmentID)})
	}
	return out, last, nil
}

func readSweptDynamicSecretLeases(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.DynamicSecretLease
	if err := tx.Select("id, lease_id, config_id, credential_enc").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read dynamic_secret_leases after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		if len(r.CredentialEnc) == 0 {
			continue
		}
		out = append(out, sweptCiphertext{table: "dynamic_secret_leases", id: r.ID, enc: r.CredentialEnc,
			aad: DynamicSecretLeaseAAD(r.LeaseID, r.ConfigID)})
	}
	return out, last, nil
}

func readSweptNotificationChannels(tx *gorm.DB, after uint, limit int) ([]sweptCiphertext, uint, error) {
	var rows []models.NotificationChannel
	if err := tx.Select("id, url_enc").Where("id > ?", after).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("read notification_channels after id %d: %w", after, err)
	}
	out := make([]sweptCiphertext, 0, len(rows))
	var last uint
	for _, r := range rows {
		last = r.ID
		tag, payload, err := NotificationChannelURLUnwrap(r.URLEnc)
		if err != nil {
			return nil, 0, fmt.Errorf("notification_channels id=%d: %w", r.ID, err)
		}
		switch tag {
		case NotificationChannelURLTagAbsent:
			continue
		case NotificationChannelURLTagPlaintext:
			// The sweep encrypts every plaintext URL; one left means it skipped the row.
			return nil, 0, fmt.Errorf("notification_channels id=%d is still plaintext after the sweep", r.ID)
		}
		out = append(out, sweptCiphertext{table: "notification_channels", id: r.ID, enc: payload, aad: NotificationChannelURLAAD(r.ID)})
	}
	return out, last, nil
}

// sweptRowCount is the number of ciphertexts the sweep rewrote, the count
// verifySweptRows must open.
func (r *SweepResult) sweptRowCount() int {
	return r.SecretVersionsSwept + r.APITokensSwept + r.APIClientsSwept + r.AccountResetsSwept +
		r.MFASecretsSwept + r.DynamicSecretConfigsSwept + r.DynamicSecretLeasesSwept + r.NotificationChannelsSwept
}

// verifySweepBeforeCommit runs verifySweptRows and checks its count against
// the sweep's. Called inside the sweep transaction, before the commit.
func verifySweepBeforeCommit(tx *gorm.DB, newSvc *EncryptionService, result *SweepResult) error {
	opened, err := verifySweptRows(tx, newSvc)
	if err != nil {
		return err
	}
	if want := result.sweptRowCount(); opened != want {
		return fmt.Errorf("%w: the sweep rewrote %d encrypted values but %d are in the database now", ErrSweepVerification, want, opened)
	}
	log.Printf("[sweep] pre-commit verification: all %d re-encrypted values decrypt under the new DEK", opened)
	return nil
}

// rewrapCanary round-trips the newest secret versions (old DEK → new DEK →
// plaintext) before the sweep writes anything. See the file comment.
func rewrapCanary(tx *gorm.DB, oldSvc, newSvc *EncryptionService, newKeyVersion string) error {
	var rows []models.SecretVersion
	if err := tx.Select("id, secret_node_id, version_number, encrypted_value").
		Where("encrypted_value IS NOT NULL").Order("id DESC").Limit(rewrapCanarySize).Find(&rows).Error; err != nil {
		return fmt.Errorf("%w: read the canary sample: %v", ErrSweepVerification, err)
	}
	for _, r := range rows {
		if len(r.EncryptedValue) == 0 {
			continue
		}
		var node models.SecretNode
		if err := tx.Unscoped().Select("id, project_id").Where("id = ?", r.SecretNodeID).Limit(1).Find(&node).Error; err != nil {
			return fmt.Errorf("%w: read secret node %d: %v", ErrSweepVerification, r.SecretNodeID, err)
		}
		if node.ID == 0 {
			// The sweep reports a version without a node itself.
			continue
		}
		if err := canaryRoundTrip(oldSvc, newSvc, newKeyVersion, r, SecretAAD(r.SecretNodeID, node.ProjectID, r.VersionNumber)); err != nil {
			return fmt.Errorf("%w: canary secret_versions id=%d (secret_node_id=%d version=%d): %v", ErrSweepVerification, r.ID, r.SecretNodeID, r.VersionNumber, err)
		}
	}
	return nil
}

func canaryRoundTrip(oldSvc, newSvc *EncryptionService, newKeyVersion string, r models.SecretVersion, aad []byte) error {
	ed, err := DeserializeEncryptedData(r.EncryptedValue)
	if err != nil {
		return err
	}
	var want []byte
	if ed.Metadata.AADVersion == "" {
		want, err = oldSvc.Decrypt(ed)
	} else {
		want, err = oldSvc.DecryptWithAAD(ed, aad)
	}
	if err != nil {
		return fmt.Errorf("does not decrypt under the current DEK: %w", err)
	}
	defer wipeBytes(want)
	sealed, err := newSvc.EncryptWithAAD(want, newKeyVersion, aad)
	if err != nil {
		return fmt.Errorf("re-encrypt under the new DEK: %w", err)
	}
	got, err := newSvc.DecryptWithAAD(sealed, aad)
	if err != nil {
		return fmt.Errorf("the new DEK does not open its own ciphertext: %w", err)
	}
	defer wipeBytes(got)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return errors.New("the new DEK round trip returned a different value")
	}
	return nil
}
