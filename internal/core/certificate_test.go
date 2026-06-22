package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// selfSignedPEM mints a self-signed P-256 cert valid until notAfter and returns its
// PEM, plus the PEM of its private key (to prove the key is never surfaced).
func selfSignedPEM(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn, "www." + cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func newCertCore(t *testing.T, now time.Time) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}))
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}, db
}

// mkCertSecret stores a secret (no encryption → value lives in the version row).
func mkCertSecret(t *testing.T, db *gorm.DB, id uint, name, status string, value []byte) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretNode{ID: id, Name: name, IsSecret: true, Status: status, Type: "certificate"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: id, VersionNumber: 1, EncryptedValue: value}).Error)
}

func TestInspectCertificate(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, _ := selfSignedPEM(t, "example.com", now.Add(90*24*time.Hour))
	mkCertSecret(t, db, 1, "tls-cert", "active", certPEM)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.Contains(t, info.Subject, "example.com")
	assert.Contains(t, info.Issuer, "example.com")
	assert.True(t, info.SelfSigned)
	assert.False(t, info.IsExpired)
	assert.Equal(t, 90, info.DaysUntilExpiry)
	assert.ElementsMatch(t, []string{"example.com", "www.example.com"}, info.DNSNames)
	assert.NotEmpty(t, info.SignatureAlgorithm)
	assert.Equal(t, "4242", info.SerialNumber)
}

func TestInspectCertificateExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, _ := selfSignedPEM(t, "old.example.com", now.Add(-10*24*time.Hour)) // expired 10 days ago
	mkCertSecret(t, db, 1, "expired-cert", "active", certPEM)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.True(t, info.IsExpired)
	assert.Less(t, info.DaysUntilExpiry, 0)
}

// A value that bundles the cert AND its private key (the common TLS layout) still
// parses to the cert, and the response never carries the key.
func TestInspectCertificateWithBundledKey(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, keyPEM := selfSignedPEM(t, "bundle.example.com", now.Add(30*24*time.Hour))
	bundle := append(append([]byte{}, certPEM...), keyPEM...)
	mkCertSecret(t, db, 1, "tls-bundle", "active", bundle)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.Contains(t, info.Subject, "bundle.example.com")
	// CertificateInfo has no field that could carry key material — public metadata only.
}

func TestInspectCertificateNotACert(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	mkCertSecret(t, db, 1, "db-password", "active", []byte("hunter2-not-a-cert"))

	_, err := c.InspectCertificate(ctx, 9, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
}

func TestInspectCertificateSuspended(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, _ := selfSignedPEM(t, "frozen.example.com", now.Add(30*24*time.Hour))
	mkCertSecret(t, db, 1, "frozen", SecretStatusSuspended, certPEM)

	_, err := c.InspectCertificate(ctx, 9, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}
