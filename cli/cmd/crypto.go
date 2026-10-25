// crypto.go implements `keyorix crypto inventory` (RD-CBOM-1): the metadata-only
// inventory of every key and certificate the server holds, scored for quantum
// exposure, as a table, JSON, or a CycloneDX 1.6 CBOM. Transport only: the server
// (GET /api/v1/compliance/crypto-inventory, audit.read, audited) builds everything;
// this command never sees key material because the server never emits any.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var cryptoCmd = &cobra.Command{
	Use:   "crypto",
	Short: "Cryptographic inventory and quantum-risk reporting",
}

func init() {
	cryptoCmd.AddCommand(cryptoInventoryCmd)
	rootCmd.AddCommand(cryptoCmd)
	cryptoInventoryCmd.Flags().StringVar(&cryptoInventoryFormat, "format", "table", "output format: table, json or cbom (CycloneDX 1.6)")
	cryptoInventoryCmd.Flags().StringVarP(&cryptoInventoryOutput, "output", "o", "", "write the json or cbom output to this file (mode 0600) instead of stdout")
	cryptoInventoryCmd.Flags().BoolVar(&cryptoInventoryForce, "force", false, "with --output: overwrite an existing file")
}

var (
	cryptoInventoryFormat string
	cryptoInventoryOutput string
	cryptoInventoryForce  bool
)

type cryptoInventoryData struct {
	GeneratedAt string `json:"generated_at"`
	Policy      struct {
		Horizon string `json:"horizon"`
	} `json:"policy"`
	Assets []struct {
		ID          string `json:"id"`
		Algorithm   string `json:"algorithm"`
		KeySizeBits int    `json:"key_size_bits"`
		ExpiresAt   string `json:"expires_at"`
		Storage     string `json:"storage"`
		Risk        struct {
			Score             int    `json:"score"`
			Level             string `json:"level"`
			QuantumVulnerable bool   `json:"quantum_vulnerable"`
		} `json:"risk"`
	} `json:"assets"`
	Summary struct {
		Total             int `json:"total"`
		High              int `json:"high"`
		Medium            int `json:"medium"`
		Low               int `json:"low"`
		QuantumVulnerable int `json:"quantum_vulnerable"`
	} `json:"summary"`
	Warnings []string `json:"warnings"`
}

var cryptoInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "List every key and certificate the server holds, with a quantum-risk score",
	Long: `List every key and certificate the server holds or depends on (KEK, DEK, recovery
key verifier, TLS certificates, derived signing/HMAC keys, WebAuthn and OIDC
verification keys): algorithm, size, expiry, where it is stored, and a quantum-risk
score (0-100) from its remaining lifetime against the configured quantum horizon.
Classical public-key keys (RSA, ECDSA, Ed25519) are flagged QUANTUM-VULNERABLE.

The output holds metadata only, never key material. --format cbom emits a CycloneDX
1.6 cryptographic bill of materials. Requires the audit.read permission; each read is
recorded in the audit log.`,
	Example: `  keyorix crypto inventory
  keyorix crypto inventory --format json
  keyorix crypto inventory --format cbom --output keyorix.cbom.json`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		format := strings.ToLower(cryptoInventoryFormat)
		switch format {
		case "table", "json", "cbom":
		default:
			return fmt.Errorf("unknown --format %q: choose table, json or cbom", cryptoInventoryFormat)
		}
		if cryptoInventoryOutput != "" && format == "table" {
			return fmt.Errorf("--output is only valid with --format json or --format cbom")
		}
		ctx := context.Background()
		client, err := apiClientWithSkewCheck(ctx)
		if err != nil {
			return err
		}
		f := apiclient.GetCryptoInventoryParamsFormat("json")
		if format == "cbom" {
			f = apiclient.Cbom
		}
		resp, err := client.GetCryptoInventoryWithResponse(ctx, &apiclient.GetCryptoInventoryParams{Format: &f})
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("get crypto inventory", resp.StatusCode(), resp.Body)
		}
		switch format {
		case "cbom":
			return emitCSV(resp.Body, cryptoInventoryOutput, "CycloneDX CBOM", cryptoInventoryForce)
		case "json":
			raw, err := decodeData[json.RawMessage](resp.Body)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err := json.Indent(&buf, raw, "", "  "); err != nil {
				return err
			}
			buf.WriteByte('\n')
			return emitCSV(buf.Bytes(), cryptoInventoryOutput, "crypto inventory JSON", cryptoInventoryForce)
		}
		inv, err := decodeData[cryptoInventoryData](resp.Body)
		if err != nil {
			return err
		}
		printCryptoInventoryTable(inv)
		return nil
	},
}

func printCryptoInventoryTable(inv cryptoInventoryData) {
	horizon := inv.Policy.Horizon
	if t, err := time.Parse(time.RFC3339, horizon); err == nil {
		horizon = t.Format("2006-01-02")
	}
	fmt.Printf("Crypto inventory — %s (quantum horizon %s)\n\n", cliout.SanitizeForTerminal(inv.GeneratedAt), cliout.SanitizeForTerminal(horizon))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tALGORITHM\tSIZE\tEXPIRES\tRISK\tFLAG")
	for _, a := range inv.Assets {
		size, expires, flag := "-", "-", ""
		if a.KeySizeBits > 0 {
			size = fmt.Sprint(a.KeySizeBits)
		}
		if t, err := time.Parse(time.RFC3339, a.ExpiresAt); err == nil {
			expires = t.Format("2006-01-02")
		}
		if a.Risk.QuantumVulnerable {
			flag = "QUANTUM-VULNERABLE"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d %s\t%s\n",
			cliout.SanitizeForTerminal(a.ID), cliout.SanitizeForTerminal(a.Algorithm), size, expires,
			a.Risk.Score, cliout.SanitizeForTerminal(a.Risk.Level), flag)
	}
	_ = tw.Flush()
	fmt.Printf("\n%d assets: %d high, %d medium, %d low; %d quantum-vulnerable\n",
		inv.Summary.Total, inv.Summary.High, inv.Summary.Medium, inv.Summary.Low, inv.Summary.QuantumVulnerable)
	for _, w := range inv.Warnings {
		fmt.Printf("warning: %s\n", cliout.SanitizeForTerminal(w))
	}
}
