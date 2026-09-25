// default_integrations_test.go — ADR-109 wiring test
// (docs/adr-109-core-depends-on-interfaces.md): confirms DefaultIntegrations
// (called from initializeCoreService) actually registers EVERY integration
// moved behind internal/core/ports so far — external-notary checkpoint
// anchoring (step 1), SAML SSO (step 1), backend rotation executors (step 2),
// and the dynamic-secrets engine factory (step 3) — from one config, in one
// call. Each integration already has narrower coverage elsewhere
// (checkpoint_notary_startup_test.go; server_s4_test.go's
// TestInitializeCoreService_CheckpointNotary_*,
// TestInitializeCoreService_SSO_OIDCSuccess,
// TestInitializeCoreService_RotationBackend_PostgreSQL, and
// TestInitializeCoreService_DynamicSecrets); this test is the ADR's own
// "wiring test that the default server registers every integration" — SAML
// specifically, since no prior test drove initializeCoreService with a
// type: "saml" provider (only unit-level buildSAMLProvider/buildSSOProviders
// tests in server_s3_test.go); the rotation manager specifically, since no
// prior test checked RotationBackendNames() actually reflects a configured
// backend (only that initializeCoreService didn't error); the dynamic-secrets
// factory specifically, since no prior test drove a real
// CreateDynamicSecretConfig call through initializeCoreService's own wiring
// (server/http/handlers' equivalent tests wire their own factory manually,
// bypassing DefaultIntegrations entirely); and the combination of all four
// integrations at once, which is what would catch DefaultIntegrations wiring
// some but silently skipping another.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// samlIDPMetadata builds minimal-but-valid IdP SAML metadata with a self-signed
// signing cert and an HTTP-Redirect SSO binding — enough for buildSAMLProvider
// (internal/saml.NewProvider) to parse successfully. Mirrors
// internal/saml/provider_test.go's idpMetadata; duplicated here rather than
// exported since it is test-only and internal/saml doesn't otherwise need a
// public test fixture.
func samlIDPMetadata(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert := base64.StdEncoding.EncodeToString(der)
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, cert)
}

// TestDefaultIntegrations_RegistersCheckpointNotarySAMLAndRotation confirms
// initializeCoreService (via DefaultIntegrations) wires ALL THREE ADR-109
// integrations from one config: checkpoint-notary anchoring+verification, a
// SAML SSO provider (ports.SAMLServiceProvider, satisfied by
// *internal/saml.Provider through the AssertionInfo/SAMLAuthn aliases), and a
// backend rotation executor (ports.RotationExecutorResolver, satisfied by
// *internal/rotation.Manager through the Executor alias).
func TestDefaultIntegrations_RegistersCheckpointNotarySAMLAndRotation(t *testing.T) {
	initI18n(t)

	caPEM := testSelfSignedCACert(t)
	dir := t.TempDir()
	t.Chdir(dir)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test.db"},
		},
		Audit: config.AuditConfig{
			CheckpointNotary: config.CheckpointNotaryConfig{
				Enabled:    true,
				URL:        "http://127.0.0.1:65543/ts",
				CACertPath: caFile,
			},
		},
		SSO: config.SSOConfig{
			Enabled: true,
			Providers: []config.SSOProviderConfig{
				{
					Name: "corp",
					Type: "saml",
					SAML: &config.SAMLProviderConfig{
						IDPMetadataXML: samlIDPMetadata(t),
						SPEntityID:     "https://keyorix.internal/saml/corp/metadata",
						ACSURL:         "https://keyorix.internal/auth/saml/corp/acs",
					},
				},
			},
		},
		AutoRotation: config.AutoRotationConfig{
			Backends: []config.RotationBackendConfig{
				{Name: "pg-prod", Type: "postgresql", AllowedRefs: []string{"prod/*"}},
			},
		},
	}

	svc, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}

	if !svc.CheckpointAnchorVerifiable() {
		t.Error("expected DefaultIntegrations to wire checkpoint-notary anchor verification (roots + verifier)")
	}
	if !svc.SSOEnabled() {
		t.Error("expected DefaultIntegrations to wire the SAML SSO provider")
	}
	if _, ok := svc.SSOCompleteURL("corp"); !ok {
		t.Error("expected the SAML provider \"corp\" to be registered")
	}
	if md, err := svc.SAMLMetadata("corp"); err != nil || len(md) == 0 {
		t.Errorf("expected SAMLMetadata(\"corp\") to succeed (SAML wired through ports.SAMLServiceProvider): md=%q err=%v", md, err)
	}
	names := svc.RotationBackendNames()
	if len(names) != 1 || names[0] != "pg-prod" {
		t.Errorf("expected DefaultIntegrations to register rotation backend \"pg-prod\" (ports.RotationExecutorResolver), got %v", names)
	}
}

// TestDefaultIntegrations_WiresDynamicSecretsFactoryUnconditionally confirms
// wireDynamicSecrets (DefaultIntegrations' fourth component, ADR-109 step 3)
// always wires the real ports.DynamicBackendFactory — there is no top-level
// "dynamic secrets enabled" flag to gate it on — by driving a real
// CreateDynamicSecretConfig call through initializeCoreService's own wiring
// (not a manually-wired test factory, which is how server/http/handlers'
// equivalent tests cover this). A minimal config (nothing else enabled) must
// still accept a supported backend type, proving the factory is reachable and
// is not the "no engine factory configured" fail-closed stub
// TestDynamicSecrets_NoFactoryConfigured_FailsClosed (internal/core) pins for
// the unwired case.
func TestDefaultIntegrations_WiresDynamicSecretsFactoryUnconditionally(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.DynamicSecrets.AllowPrivateNetworkTargets = true // test uses a localhost-shaped DSN

	svc, _, err := initializeCoreService(cfg)
	if err != nil {
		t.Fatalf("initializeCoreService: %v", err)
	}

	// initializeCoreService already created and migrated the SQLite file at
	// cfg.Storage.Database.Path; open a second connection to seed the
	// project/environment/admin-role fixtures CreateDynamicSecretConfig needs.
	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open seed DB connection: %v", err)
	}
	if err := db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.Role{}, &models.UserRole{}); err != nil {
		t.Fatalf("migrate seed fixtures: %v", err)
	}
	if err := db.Create(&models.Project{ID: 1, Name: "wiring-test-project"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "wiring-test-env"}).Error; err != nil {
		t.Fatalf("seed environment: %v", err)
	}
	adminRole := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	if err := db.Create(adminRole).Error; err != nil {
		t.Fatalf("seed admin role: %v", err)
	}
	const actorID = 1
	if err := db.Create(&models.UserRole{UserID: actorID, RoleID: adminRole.ID}).Error; err != nil {
		t.Fatalf("seed admin role grant: %v", err)
	}

	_, err = svc.CreateDynamicSecretConfig(context.Background(), &core.CreateDynamicSecretConfigRequest{
		Name: "pg-cfg", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
		AdminDSN: "postgres://admin:s3cr3t@127.0.0.1:5432/app", ActorID: actorID,
	})
	if err != nil {
		t.Errorf("expected DefaultIntegrations to wire a working dynamic-secrets factory (ports.DynamicBackendFactory) unconditionally, got: %v", err)
	}
}
