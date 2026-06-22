// certificate.go — the `keyorix secret cert` CLI (ADR-054): show the public X.509
// metadata of a certificate-valued secret (subject, issuer, validity, SANs) so an
// operator can check PKI hygiene from the terminal. Talks to
// GET /api/v1/secrets/{id}/certificate; never prints the value or any private key.
package secret

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

type certView struct {
	SecretID           uint     `json:"secret_id"`
	SecretName         string   `json:"secret_name"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysUntilExpiry    int      `json:"days_until_expiry"`
	IsExpired          bool     `json:"is_expired"`
	IsCA               bool     `json:"is_ca"`
	SelfSigned         bool     `json:"self_signed"`
	DNSNames           []string `json:"dns_names"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
}

var certCmd = &cobra.Command{
	Use:          "cert <secret-id>",
	Aliases:      []string{"certificate"},
	Short:        "Show a certificate secret's public X.509 metadata (expiry, issuer, SANs)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := depsClient()
		if err != nil {
			return err
		}
		var v certView
		if err := c.Get(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/certificate", id), &v); err != nil {
			return err
		}
		expiry := v.NotAfter
		if v.IsExpired {
			expiry += "  (EXPIRED)"
		} else {
			expiry += fmt.Sprintf("  (%d days left)", v.DaysUntilExpiry)
		}
		fmt.Printf("Certificate: %s (secret %d)\n", v.SecretName, v.SecretID)
		fmt.Printf("  Subject:    %s\n", v.Subject)
		fmt.Printf("  Issuer:     %s%s\n", v.Issuer, selfSignedNote(v.SelfSigned))
		fmt.Printf("  Serial:     %s\n", v.SerialNumber)
		fmt.Printf("  Valid from: %s\n", v.NotBefore)
		fmt.Printf("  Expires:    %s\n", expiry)
		if len(v.DNSNames) > 0 {
			fmt.Printf("  SANs:       %v\n", v.DNSNames)
		}
		fmt.Printf("  CA:         %t\n", v.IsCA)
		fmt.Printf("  Algorithms: %s / %s\n", v.SignatureAlgorithm, v.PublicKeyAlgorithm)
		return nil
	},
}

func selfSignedNote(selfSigned bool) string {
	if selfSigned {
		return "  (self-signed)"
	}
	return ""
}

func init() {
	SecretCmd.AddCommand(certCmd)
}
