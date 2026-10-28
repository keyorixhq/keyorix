// crypto_inventory.go — GET /api/v1/compliance/crypto-inventory: the metadata-only
// inventory of every key and certificate Keyorix holds, scored for quantum
// exposure, as JSON or as a CycloneDX 1.6 CBOM (RD-CBOM-1).
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
	if c.MigrationYears != nil {
		p.MigrationYears = *c.MigrationYears
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

	if cfg.WebAuthn.Enabled {
		creds, complete, warn := webAuthnInventoryCredentials(ctx, coreService.Storage())
		in.WebAuthnCredentials, in.WebAuthnEnumerated = creds, complete
		if warn != "" {
			warnings = append(warnings, warn)
		}
	}

	in.Backup = &cryptoinventory.BackupInput{EncryptionEnabled: enc.Enabled, ShamirShareFiles: backedUpShamirShareFiles(enc.KeyProvider)}
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

// backedUpShamirShareFiles counts the Shamir share files `admin backup` writes
// into the archive: keyfiles.Registry backs up shamir_share_files of the primary
// key provider and of each fallback (one level). Kept equal to the registry by
// TestBackedUpShamirShareFiles_MatchesKeyfilesRegistry.
func backedUpShamirShareFiles(kp config.KeyProviderConfig) int {
	n := 0
	for _, p := range append([]config.KeyProviderConfig{kp}, kp.Fallbacks...) {
		if p.Type != "shamir" {
			continue
		}
		for _, f := range p.ShamirShareFiles {
			if f != "" {
				n++
			}
		}
	}
	return n
}

// dekCreatedAt dates the DEK. The recorded time is the dek.created_at row
// (encryption.DEKCreatedAt, PostgreSQL), written when the epoch is seeded and in
// the transaction that makes a rotated DEK current, and used only when it names
// the DEK the settled epoch names. The epoch row's own updated_at is not used: a
// failed or interrupted rotation rewrites it when its fence is lifted, with the
// old DEK still current. The key-set manifest records generations and hashes, no
// time. Without a matching row (SQLite, a rotation in flight, an epoch seeded
// before the row existed, a read error) it falls back to the key file's mtime,
// which also moves on KEK rewrap, and says it is estimated. Only system_metadata
// and os.Stat are used: the key file is never opened.
func dekCreatedAt(ctx context.Context, dekPath string, st interface {
	GetSystemMetadata(ctx context.Context, key string) (string, bool, error)
}) (t *time.Time, estimated bool) {
	if at, ok := recordedDEKCreatedAt(ctx, st); ok {
		return &at, false
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

func recordedDEKCreatedAt(ctx context.Context, st interface {
	GetSystemMetadata(ctx context.Context, key string) (string, bool, error)
}) (time.Time, bool) {
	epoch, found, err := st.GetSystemMetadata(ctx, encryption.DEKEpochMetadataKey)
	if err != nil {
		log.Printf("crypto inventory: dek epoch: %v", err)
		return time.Time{}, false
	}
	if !found {
		return time.Time{}, false
	}
	recorded, found, err := st.GetSystemMetadata(ctx, encryption.DEKCreatedAtMetadataKey)
	if err != nil {
		log.Printf("crypto inventory: dek created_at: %v", err)
		return time.Time{}, false
	}
	if !found {
		return time.Time{}, false
	}
	return encryption.DEKCreatedAt(epoch, recorded)
}

const (
	// webAuthnListPageSize / webAuthnListMaxUsers bound the deployment-wide walk.
	webAuthnListPageSize = 200
	webAuthnListMaxUsers = 5000
)

// webAuthnWalkStore is the part of the storage the WebAuthn walk reads.
type webAuthnWalkStore interface {
	ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error)
	ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error)
}

// webAuthnInventoryCredentials lists every stored passkey's public key by walking
// the users with the EXISTING per-user ListWebAuthnCredentials: a deployment-wide
// listing method on the storage interface was deliberately not added (it is the
// hot interface every wrapper and fault double implements). The cost is one
// credential query per user, acceptable for an audit.read-gated report that is
// read rarely and is capped at webAuthnListMaxUsers users. complete is false when
// the walk failed or was capped, in which case the generic WebAuthn asset is
// kept and warn says why. Only credential_blob's public key is decoded here.
//
// ListUsers pages by OFFSET without a guaranteed order, so pages may overlap and
// skip users (PostgreSQL), and users created or deleted during the walk shift
// them. The walk is complete only when the user total stayed the same on every
// page and that many distinct users were seen; a skip with a stable total shows
// up as a repeat. Not detected: a create and a delete between two pages that
// leave the total unchanged while shifting a user past the walk.
func webAuthnInventoryCredentials(ctx context.Context, st webAuthnWalkStore) (creds []cryptoinventory.WebAuthnCredentialInput, complete bool, warn string) {
	const listFailed = "WebAuthn credentials could not be listed; the per-credential algorithms are missing from this inventory"
	seen := map[uint]bool{}
	seenUsers := map[uint]bool{}
	firstTotal := int64(-1)
	for page := 1; ; page++ {
		batch, total, err := st.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: webAuthnListPageSize, IncludeDeleted: true})
		if err != nil {
			log.Printf("crypto inventory: list users for webauthn: %v", err)
			return nil, false, listFailed
		}
		if firstTotal < 0 {
			firstTotal = total
		} else if total != firstTotal {
			return nil, false, "WebAuthn credentials were not enumerated: users were added or removed during the listing; read the inventory again"
		}
		for _, u := range batch {
			if seenUsers[u.ID] {
				continue
			}
			seenUsers[u.ID] = true
			rows, err := st.ListWebAuthnCredentials(ctx, u.ID)
			if err != nil {
				log.Printf("crypto inventory: list webauthn credentials: %v", err)
				return nil, false, listFailed
			}
			for _, r := range rows {
				if seen[r.ID] {
					continue
				}
				seen[r.ID] = true
				var blob struct {
					PublicKey []byte `json:"publicKey"`
				}
				// An undecodable blob is passed on empty: the inventory records it as
				// an unclassifiable credential rather than dropping it.
				if err := json.Unmarshal(r.CredentialBlob, &blob); err != nil {
					blob.PublicKey = nil
				}
				creds = append(creds, cryptoinventory.WebAuthnCredentialInput{PublicKey: blob.PublicKey, CreatedAt: r.CreatedAt})
			}
		}
		if len(batch) == 0 || int64(page)*webAuthnListPageSize >= total {
			if int64(len(seenUsers)) != total {
				log.Printf("crypto inventory: webauthn walk saw %d distinct users of %d", len(seenUsers), total)
				return nil, false, "WebAuthn credentials were not enumerated: the user listing was not stable while it was read; read the inventory again"
			}
			return creds, true, ""
		}
		if len(seenUsers) >= webAuthnListMaxUsers {
			return nil, false, fmt.Sprintf("WebAuthn credentials were not enumerated: more than %d users", webAuthnListMaxUsers)
		}
	}
}
