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
	if enc.Enabled && enc.DEKPath != "" {
		// The key file's mtime is the closest thing to a creation date (it moves on
		// DEK rotation and KEK rewrap). Only os.Stat: the file is never opened.
		if st, err := os.Stat(enc.DEKPath); err == nil {
			t := st.ModTime().UTC()
			in.DEKCreatedAt = &t
		}
	}

	for _, t := range []struct {
		name string
		tls  config.TLSConfig
	}{{"http", cfg.Server.HTTP.TLS}, {"grpc", cfg.Server.GRPC.TLS}} {
		if !t.tls.Enabled {
			continue
		}
		in.TLS = append(in.TLS, cryptoinventory.TLSInput{Name: t.name, CertFile: t.tls.CertFile, KeyFile: t.tls.KeyFile, AutoCert: t.tls.AutoCert})
	}

	if cfg.OIDC.Enabled {
		for _, iss := range cfg.OIDC.Issuers {
			in.OIDCIssuers = append(in.OIDCIssuers, iss.Issuer)
		}
	}
	if cfg.SSO.Enabled {
		for _, p := range cfg.SSO.Providers {
			if p.Type == "" || p.Type == "oidc" {
				in.OIDCIssuers = append(in.OIDCIssuers, p.Issuer)
			}
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
