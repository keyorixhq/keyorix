// crypto_inventory.go — GET /api/v1/compliance/crypto-inventory: the metadata-only
// inventory of every key and certificate Keyorix holds, scored for quantum
// exposure, as JSON or as a CycloneDX 1.6 CBOM (RD-CBOM-1).
package handlers

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const (
	cryptoInventoryFormatJSON = "json"
	cryptoInventoryFormatCBOM = "cbom"
)

// MakeCryptoInventoryHandler serves the crypto inventory. Gated by audit.read at
// the router (a deployment-wide disclosure of key locations, like
// /compliance/evidence); every successful read is audited. ?format=json (default)
// returns the API envelope, ?format=cbom a bare CycloneDX 1.6 document.
func MakeCryptoInventoryHandler(cfg *config.Config, coreService *core.KeyorixCore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx := middleware.GetUserFromContext(r.Context())
		if userCtx == nil {
			sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			format = cryptoInventoryFormatJSON
		}
		if format != cryptoInventoryFormatJSON && format != cryptoInventoryFormatCBOM {
			sendError(w, "BadRequest", "format must be json or cbom", http.StatusBadRequest, nil)
			return
		}

		policy, err := cryptoInventoryPolicy(cfg.CryptoInventory)
		if err != nil {
			log.Printf("crypto inventory: %v", err)
			sendError(w, "InternalServerError", "Invalid crypto_inventory configuration", http.StatusInternalServerError, nil)
			return
		}
		in, warnings := cryptoInventoryInputs(r.Context(), cfg, coreService)
		inv := cryptoinventory.Build(in, policy, time.Now().UTC())
		inv.Warnings = append(inv.Warnings, warnings...)

		var body []byte
		if format == cryptoInventoryFormatCBOM {
			body, err = inv.CBOM(cryptoinventory.CBOMOptions{ServerVersion: version.Version})
			if err != nil {
				log.Printf("crypto inventory: cbom: %v", err)
				sendError(w, "InternalServerError", "Failed to build the CBOM", http.StatusInternalServerError, nil)
				return
			}
		}
		coreService.LogCryptoInventoryRead(r.Context(), userCtx.UserID, format, inv.Summary.Total, inv.Summary.QuantumVulnerable)

		if format == cryptoInventoryFormatCBOM {
			w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.6")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Disposition", `attachment; filename="crypto-inventory.cbom.json"`)
			_, _ = w.Write(body)
			return
		}
		sendSuccess(w, inv, "")
	}
}

// cryptoInventoryPolicy overlays the configured values on the documented defaults.
func cryptoInventoryPolicy(c config.CryptoInventoryConfig) (cryptoinventory.Policy, error) {
	p := cryptoinventory.DefaultPolicy()
	h, err := c.ParsedHorizon()
	if err != nil {
		return p, err
	}
	if !h.IsZero() {
		p.Horizon = h
	}
	if c.MigrationYears > 0 {
		p.MigrationYears = c.MigrationYears
	}
	if c.UnboundedLifetimeYears > 0 {
		p.UnboundedLifetimeYears = c.UnboundedLifetimeYears
	}
	return p, nil
}

// cryptoInventoryInputs gathers locations and non-secret identifiers from
// configuration and storage. It never opens a key file or reads a key, a
// passphrase, an environment variable value or a stored hash; the second return
// lists anything that could not be gathered.
func cryptoInventoryInputs(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) (cryptoinventory.Inputs, []string) {
	var warnings []string
	enc := cfg.Storage.Encryption
	in := cryptoinventory.Inputs{
		EncryptionEnabled: enc.Enabled,
		KeyProvider:       enc.KeyProvider.Type,
		KeyProviderRef:    keyProviderRef(enc.KeyProvider),
		DEKPath:           enc.DEKPath,
		WebAuthnEnabled:   cfg.WebAuthn.Enabled,
		WebAuthnRPID:      cfg.WebAuthn.RPID,
	}
	for _, fb := range enc.KeyProvider.Fallbacks {
		in.FallbackProviders = append(in.FallbackProviders, fb.Type)
	}
	if enc.Enabled {
		in.DEKCreatedAt, in.DEKCreatedAtEstimated = dekCreatedAt(ctx, enc.DEKPath, coreService.Storage())
	}

	// A listener that is switched off holds no live certificate, whatever its
	// tls block says.
	for _, l := range []struct {
		name string
		inst config.ServerInstanceConfig
	}{{"http", cfg.Server.HTTP}, {"grpc", cfg.Server.GRPC}} {
		if !l.inst.Enabled || !l.inst.TLS.Enabled {
			continue
		}
		t := l.inst.TLS
		in.TLS = append(in.TLS, cryptoinventory.TLSInput{Name: l.name, CertFile: t.CertFile, KeyFile: t.KeyFile, AutoCert: t.AutoCert})
	}

	if cfg.OIDC.Enabled {
		for _, iss := range cfg.OIDC.Issuers {
			in.OIDCIssuers = append(in.OIDCIssuers, iss.Issuer)
		}
	}
	if cfg.SSO.Enabled {
		for _, p := range cfg.SSO.Providers {
			switch {
			case p.Type == "" || p.Type == "oidc":
				in.OIDCIssuers = append(in.OIDCIssuers, p.Issuer)
			case p.Type == "saml" && p.SAML != nil:
				in.SAML = append(in.SAML, samlInput(p))
			}
		}
	}

	in.Backup = &cryptoinventory.BackupInput{EncryptionEnabled: enc.Enabled}
	if st := cfg.Storage.Type; st == "postgres" || st == "postgresql" {
		files, err := config.DatabaseTLSFilesOf(&cfg.Storage.Database)
		if err != nil {
			log.Printf("crypto inventory: database TLS settings: %v", err)
			warnings = append(warnings, "the database TLS settings could not be read; the database TLS certificates are missing from this inventory")
		} else {
			in.Database = &cryptoinventory.DatabaseTLSInput{SSLMode: files.SSLMode, RootCertFile: files.RootCert,
				RootCertSystem: files.RootCertSystem, ClientCertFile: files.ClientCert, ClientKeyFile: files.ClientKey}
		}
	}

	rec, found, err := coreService.Storage().GetRecoveryKeyRecord(ctx)
	switch {
	case err != nil:
		log.Printf("crypto inventory: recovery key record: %v", err)
		warnings = append(warnings, "the admin recovery key record could not be read; it is missing from this inventory")
	case found:
		in.Recovery = &cryptoinventory.RecoveryInput{KeyVersion: rec.KeyVersion, CreatedAt: rec.CreatedAt, RotatedAt: rec.RotatedAt}
	}
	return in, warnings
}

// keyProviderRef is the non-secret locator for a key provider: a file path, an env
// var NAME, a KMS key ID, a TPM device. For exec it is argv[0] only (arguments may
// embed credentials).
func keyProviderRef(kp config.KeyProviderConfig) string {
	switch kp.Type {
	case "file":
		return kp.FilePath
	case "env":
		return kp.EnvVar
	case "exec":
		if len(kp.ExecCommand) > 0 {
			return kp.ExecCommand[0]
		}
	case "tpm":
		if kp.TPMDevice != "" {
			return kp.TPMDevice
		}
		return "/dev/tpmrm0"
	case "aws-kms", "gcp-kms", "azure-kms":
		return kp.KMSKeyID
	}
	return ""
}

// samlInput reads one SAML provider's IdP metadata (inline or from its file), the
// same two sources the provider itself is built from (server/wire_sso.go). A read
// failure is carried in the input so it surfaces as a warning, not a silent gap.
func samlInput(p config.SSOProviderConfig) cryptoinventory.SAMLInput {
	in := cryptoinventory.SAMLInput{Name: p.Name, Metadata: []byte(p.SAML.IDPMetadataXML)}
	if len(in.Metadata) == 0 && p.SAML.IDPMetadataFile != "" {
		b, err := secretenv.ReadRegularFile("idp_metadata_file", p.SAML.IDPMetadataFile)
		if err != nil {
			log.Printf("crypto inventory: saml provider %q metadata: %v", p.Name, err)
			in.MetadataErr = "idp_metadata_file could not be read"
			return in
		}
		in.Metadata = b
	}
	return in
}

// systemMetadataTimes is the optional storage capability behind dekCreatedAt
// (store.SystemMetadataTimes), asserted structurally so the handler package does
// not import the store and the Storage interface does not grow a method for it.
type systemMetadataTimes interface {
	SystemMetadataUpdatedAt(ctx context.Context, key string) (time.Time, bool, error)
}

// dekCreatedAt dates the DEK. The DEK epoch row (PostgreSQL) is written when the
// epoch is seeded and again when a rotation completes, so a settled epoch's
// updated_at is the best recorded time for the current DEK; the key-set manifest
// records generations and hashes, no time. Without that row (SQLite, a backend
// that cannot report row times, a rotation in flight, a read error) it falls back
// to the key file's mtime, which also moves on KEK rewrap, and says it is
// estimated. Only the epoch row's metadata and os.Stat are used: the key file is
// never opened.
func dekCreatedAt(ctx context.Context, dekPath string, st interface {
	GetSystemMetadata(ctx context.Context, key string) (string, bool, error)
}) (t *time.Time, estimated bool) {
	if tm, ok := st.(systemMetadataTimes); ok {
		v, found, err := st.GetSystemMetadata(ctx, encryption.DEKEpochMetadataKey)
		switch {
		case err != nil:
			log.Printf("crypto inventory: dek epoch: %v", err)
		case found && v != "" && !encryption.DEKEpochIsRotating(v):
			if at, ok, err := tm.SystemMetadataUpdatedAt(ctx, encryption.DEKEpochMetadataKey); err != nil {
				log.Printf("crypto inventory: dek epoch time: %v", err)
			} else if ok && !at.IsZero() {
				return &at, false
			}
		}
	}
	if dekPath == "" {
		return nil, false
	}
	if fi, err := os.Stat(dekPath); err == nil {
		m := fi.ModTime().UTC()
		return &m, true
	}
	return nil, false
}
