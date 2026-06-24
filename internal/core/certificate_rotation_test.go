package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rotating a certificate-typed secret refreshes the cached leaf-expiry (CertNotAfter,
// ADR-056) immediately, so the certificate-hygiene posture reflects the new certificate
// without waiting for the next expiry scan.
func TestRotateSecret_RefreshesCertNotAfterCache(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)

	oldExpiry := now.Add(30 * 24 * time.Hour)
	cert1, _ := selfSignedPEM(t, "a.example.com", oldExpiry)
	mkCertSecret(t, db, 1, "tls-cert", "active", cert1)

	// Prime the cache to the old certificate's expiry (as a scan / inspection would).
	_, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	primed, err := c.storage.GetSecret(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, primed.CertNotAfter)
	assert.WithinDuration(t, oldExpiry, *primed.CertNotAfter, time.Second)

	// Rotate to a renewed certificate with a later expiry.
	newExpiry := now.Add(90 * 24 * time.Hour)
	cert2, _ := selfSignedPEM(t, "a.example.com", newExpiry)
	_, err = c.RotateSecret(ctx, 1, cert2, "tester")
	require.NoError(t, err)

	got, err := c.storage.GetSecret(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, got.CertNotAfter, "the cached expiry is refreshed on rotation")
	assert.WithinDuration(t, newExpiry, *got.CertNotAfter, time.Second,
		"CertNotAfter reflects the rotated certificate, not the old one")
}

// Rotating a non-certificate secret does not touch CertNotAfter (it stays nil).
func TestRotateSecret_NonCertSecretLeavesCertNotAfterNil(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "api-key", IsSecret: true, Status: "active", Type: "api_key"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("old-value")}).Error)

	_, err := c.RotateSecret(ctx, 1, []byte("new-random-value"), "tester")
	require.NoError(t, err)

	got, err := c.storage.GetSecret(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, got.CertNotAfter, "a non-certificate secret never gets a cached cert expiry")
}

// A certificate-typed secret rotated to a value that is not a certificate clears the now-
// stale cached expiry, rather than leaving the old certificate's date in place.
func TestRotateSecret_CertRotatedToNonCertClearsCache(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	cert1, _ := selfSignedPEM(t, "a.example.com", now.Add(30*24*time.Hour))
	mkCertSecret(t, db, 1, "tls-cert", "active", cert1)
	_, err := c.InspectCertificate(ctx, 9, 1) // prime the cache
	require.NoError(t, err)

	_, err = c.RotateSecret(ctx, 1, []byte("no-longer-a-certificate"), "tester")
	require.NoError(t, err)

	got, err := c.storage.GetSecret(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, got.CertNotAfter, "the stale cached expiry is cleared when the value is no longer a certificate")
}
