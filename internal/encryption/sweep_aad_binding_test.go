package encryption

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRotateDEKWithSweep_PreservesAADBinding pins that a DEK rotation re-encrypts secret
// rows WITH their SecretAAD binding intact — not just that they still decrypt. The sweep
// reads each row with its (secretID, projectID, versionNumber) AAD and must re-seal under
// the new key with the SAME AAD, so the ciphertext-transplant defense (see the AEAD/AAD
// tests) survives every rotation.
//
// The existing ReEncryptsAllRows test only ever decrypts with the CORRECT AAD, so it would
// NOT catch a regression that re-encrypted with the plain nil-AAD path: such a row drops to
// AADVersion="" and the legacy fallback in DecryptSecretWithAAD would still return the
// plaintext for any AAD — silently voiding transplant-resistance on every key rotation.
// This test closes that gap by asserting the re-encrypted row is still AAD-marked and
// rejects a wrong AAD.
func TestRotateDEKWithSweep_PreservesAADBinding(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	const projectID = uint(1)
	const versionNumber = 1
	nodeID := seedSecretNode(t, db, projectID)
	versionID := seedSecretVersion(t, db, svc, nodeID, projectID, versionNumber, "super-secret-value")

	_, rotErr := svc.RotateDEKWithSweep("test-passphrase", db)
	require.NoError(t, rotErr)

	var v models.SecretVersion
	require.NoError(t, db.First(&v, versionID).Error)

	// The re-encrypted row must still be AAD-bound (v2), not downgraded to the legacy path.
	enc, err := DeserializeEncryptedData(v.EncryptedValue)
	require.NoError(t, err)
	require.Equal(t, "v2", enc.Metadata.AADVersion,
		"rotation must keep the row AAD-bound, not re-encrypt it on the plain nil-AAD path")

	// Round-trips under the correct AAD.
	correct := SecretAAD(nodeID, projectID, versionNumber)
	got, err := svc.DecryptSecretWithAAD(v.EncryptedValue, correct)
	require.NoError(t, err)
	require.Equal(t, "super-secret-value", string(got))

	// And the transplant defense still holds AFTER rotation: a wrong AAD must fail. If the
	// sweep had stripped the binding, the legacy fallback would return the plaintext here.
	_, err = svc.DecryptSecretWithAAD(v.EncryptedValue, SecretAAD(nodeID+1, projectID, versionNumber))
	assert.Error(t, err, "a different secret ID must not decrypt the re-encrypted row")
	_, err = svc.DecryptSecretWithAAD(v.EncryptedValue, SecretAAD(nodeID, projectID+1, versionNumber))
	assert.Error(t, err, "a different project ID must not decrypt the re-encrypted row")
	_, err = svc.DecryptSecretWithAAD(v.EncryptedValue, SecretAAD(nodeID, projectID, versionNumber+1))
	assert.Error(t, err, "a different version number must not decrypt the re-encrypted row")
}
