// Package trust provides `keyorix trust` — local tooling for Keyorix's air-gap signing
// keys (ADR-062). `keygen` mints an ed25519 keypair: the private key is the signing
// secret (kept offline, used by Keyorix to sign update bundles / licenses) and the public
// key is embedded into release builds so deployments can verify offline.
package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	itrust "github.com/keyorixhq/keyorix/internal/trust"
	"github.com/spf13/cobra"
)

// TrustCmd is the `keyorix trust` command group.
var TrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Air-gap signing-key tooling (ed25519 keypairs for update bundles / licenses)",
	Long: `Generate and inspect the asymmetric keys Keyorix uses to sign air-gapped update
bundles and offline licenses (ADR-062). The private key never ships; its public key is
embedded into release builds so an air-gapped deployment can verify offline.`,
}

var (
	keygenPurpose string
	keygenKeyID   string
	keygenDir     string
)

var keygenCmd = &cobra.Command{
	Use:          "keygen",
	Short:        "Generate an ed25519 signing keypair (update or license)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		purpose := itrust.Purpose(strings.TrimSpace(keygenPurpose))
		var ldVar string
		switch purpose {
		case itrust.PurposeUpdate:
			ldVar = "updateKeysB64"
		case itrust.PurposeLicense:
			ldVar = "licenseKeysB64"
		default:
			return fmt.Errorf("--purpose must be %q or %q", itrust.PurposeUpdate, itrust.PurposeLicense)
		}
		keyID := strings.TrimSpace(keygenKeyID)
		if keyID == "" {
			return fmt.Errorf("--key-id is required (e.g. %s-2026)", purpose)
		}

		pub, priv, err := itrust.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("marshal private key: %w", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

		privPath := filepath.Join(keygenDir, keyID+".private.pem")
		pubPath := filepath.Join(keygenDir, keyID+".public.pem")
		// Both at 0600 — the private key is a signing secret; the public key need not be
		// world-readable here (it is published separately).
		if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
		if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}

		// The embed snippet: base64 public key keyed by key-id, for the build-time -X var.
		spec := keyID + "=" + itrust.EncodePublicKeyBase64(pub)
		fmt.Printf("Generated %s signing keypair %q:\n", purpose, keyID)
		fmt.Printf("  private key: %s  (KEEP OFFLINE — never commit or ship)\n", privPath)
		fmt.Printf("  public key:  %s\n\n", pubPath)
		fmt.Printf("Embed the public key into release builds via:\n")
		fmt.Printf("  -ldflags \"-X github.com/keyorixhq/keyorix/internal/trust.%s=%s\"\n", ldVar, spec)
		return nil
	},
}

func init() {
	keygenCmd.Flags().StringVar(&keygenPurpose, "purpose", "", "key purpose: update | license (required)")
	keygenCmd.Flags().StringVar(&keygenKeyID, "key-id", "", "key identifier, e.g. update-2026 (required)")
	keygenCmd.Flags().StringVar(&keygenDir, "dir", ".", "directory to write the keypair into")
	TrustCmd.AddCommand(keygenCmd)
}
