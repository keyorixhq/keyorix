package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const cryptoInvDEKSentinel = "SENTINEL-DEK-FILE-BYTES-MUST-NEVER-LEAK"

type cryptoInvFixture struct {
	h        http.HandlerFunc
	db       *gorm.DB
	cfg      *config.Config
	keyBytes []byte
}

func newCryptoInvFixture(t *testing.T) *cryptoInvFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.AuditEvent{}, &models.RecoveryKeyRecord{}))

	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "keyorix.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	certPath := filepath.Join(dir, "tls.pem")
	require.NoError(t, os.WriteFile(certPath, combined, 0o600))
	dekPath := filepath.Join(dir, "dek.key")
	require.NoError(t, os.WriteFile(dekPath, []byte(cryptoInvDEKSentinel), 0o600))

	cfg := &config.Config{}
	cfg.Storage.Encryption = config.EncryptionConfig{Enabled: true, DEKPath: dekPath}
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: filepath.Join(dir, "tls.key")}
	// gRPC is switched off but still carries a tls block (the generated baseline
	// config does exactly this): it holds no live certificate and must not be listed.
	cfg.Server.GRPC.Enabled = false
	cfg.Server.GRPC.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: filepath.Join(dir, "tls.key")}

	coreSvc := core.NewKeyorixCore(store.NewLocalStorage(db))
	return &cryptoInvFixture{h: MakeCryptoInventoryHandler(cfg, coreSvc), db: db, cfg: cfg, keyBytes: keyDER}
}

func (f *cryptoInvFixture) get(t *testing.T, query string, withUser bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/crypto-inventory"+query, nil)
	if withUser {
		req = withUserCtx(req)
	}
	w := httptest.NewRecorder()
	f.h(w, req)
	return w
}

func TestCryptoInventoryHandler_JSON(t *testing.T) {
	f := newCryptoInvFixture(t)
	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)

	var env struct {
		Data cryptoinventory.Inventory `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	byID := map[string]cryptoinventory.Asset{}
	for _, a := range env.Data.Assets {
		byID[a.ID] = a
	}
	require.Contains(t, byID, "tls.http")
	assert.NotContains(t, byID, "tls.grpc", "a disabled listener holds no live certificate")
	assert.True(t, byID["tls.http"].Risk.QuantumVulnerable, "ECDSA certificate must be flagged")
	assert.Equal(t, "ECDSA-P256", byID["tls.http"].Algorithm)
	require.Contains(t, byID, "dek")
	assert.False(t, byID["dek"].Risk.QuantumVulnerable)
	assert.NotNil(t, byID["dek"].CreatedAt, "DEK created_at is taken from the key file's mtime")
	assert.Equal(t, 2035, env.Data.Policy.Horizon.Year(), "documented default horizon")
	assert.GreaterOrEqual(t, env.Data.Summary.QuantumVulnerable, 1)
}

func TestCryptoInventoryHandler_HorizonFromConfig(t *testing.T) {
	f := newCryptoInvFixture(t)
	f.cfg.CryptoInventory = config.CryptoInventoryConfig{QuantumHorizon: "2031-03-04", MigrationYears: 4}
	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data cryptoinventory.Inventory `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	assert.Equal(t, 2031, env.Data.Policy.Horizon.Year())
	assert.Equal(t, 4, env.Data.Policy.MigrationYears)
	assert.Equal(t, 10, env.Data.Policy.UnboundedLifetimeYears, "unset fields keep the documented default")
}

func TestCryptoInventoryHandler_CBOM(t *testing.T) {
	f := newCryptoInvFixture(t)
	w := f.get(t, "?format=cbom", true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/vnd.cyclonedx+json")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "crypto-inventory.cbom.json")
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))

	var bom struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Type string `json:"type"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &bom), "CBOM is a bare CycloneDX document, not the API envelope")
	assert.Equal(t, "CycloneDX", bom.BomFormat)
	assert.Equal(t, "1.6", bom.SpecVersion)
	require.NotEmpty(t, bom.Components)
	for _, c := range bom.Components {
		assert.Equal(t, "cryptographic-asset", c.Type)
	}
}

func TestCryptoInventoryHandler_RejectsUnknownFormat(t *testing.T) {
	f := newCryptoInvFixture(t)
	assert.Equal(t, http.StatusBadRequest, f.get(t, "?format=xml", true).Code)
}

func TestCryptoInventoryHandler_RequiresUser(t *testing.T) {
	f := newCryptoInvFixture(t)
	assert.Equal(t, http.StatusUnauthorized, f.get(t, "", false).Code)
}

func TestCryptoInventoryHandler_NoKeyMaterialInResponses(t *testing.T) {
	f := newCryptoInvFixture(t)
	for _, q := range []string{"", "?format=json", "?format=cbom"} {
		body := f.get(t, q, true).Body.String()
		assert.NotContains(t, body, cryptoInvDEKSentinel, q)
		assert.NotContains(t, body, "PRIVATE KEY", q)
		assert.NotContains(t, body, "BEGIN CERTIFICATE", q)
		assert.NotContains(t, body, string(f.keyBytes), q)
	}
}

func TestCryptoInventoryHandler_IsAudited(t *testing.T) {
	f := newCryptoInvFixture(t)
	require.Equal(t, http.StatusOK, f.get(t, "?format=cbom", true).Code)

	var events []models.AuditEvent
	require.NoError(t, f.db.Where("event_type = ?", core.EventCryptoInventoryRead).Find(&events).Error)
	require.Len(t, events, 1, "every successful read is audited exactly once")
	assert.Contains(t, events[0].Description, "cbom")
	assert.NotContains(t, events[0].Description, cryptoInvDEKSentinel)

	// A rejected request discloses nothing and so records nothing.
	require.Equal(t, http.StatusBadRequest, f.get(t, "?format=xml", true).Code)
	require.Equal(t, http.StatusUnauthorized, f.get(t, "", false).Code)
	var n int64
	require.NoError(t, f.db.Model(&models.AuditEvent{}).Where("event_type = ?", core.EventCryptoInventoryRead).Count(&n).Error)
	assert.EqualValues(t, 1, n)
}

func TestCryptoInventoryHandler_IncludesRecoveryKeyWithoutHash(t *testing.T) {
	f := newCryptoInvFixture(t)
	rot := time.Now().Add(-24 * time.Hour)
	require.NoError(t, f.db.Create(&models.RecoveryKeyRecord{
		KeyHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", KeyVersion: 3,
		CreatedAt: time.Now().Add(-48 * time.Hour), RotatedAt: &rot,
	}).Error)
	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "recovery-key")
	assert.NotContains(t, w.Body.String(), "deadbeef", "the stored verifier hash is not exported")
}
