// rotation_dryrun.go — CLI command for rotation dry-run / simulation.
//
// Usage: keyorix secret rotation-simulate --id <secret-id>
//
// Simulates a rotation for the given secret without making any live changes:
// validates the rotation policy, backend and ref, then prints a table of
// check results and an overall PASS / FAIL status.
package secret

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var rotationSimulateID uint

// rotationDryRunResult mirrors core.RotationDryRunResult.
type rotationDryRunResult struct {
	SecretID    uint                  `json:"secret_id"`
	SecretName  string                `json:"secret_name"`
	Backend     string                `json:"backend"`
	Ref         string                `json:"ref"`
	Valid       bool                  `json:"valid"`
	Checks      []rotationDryRunCheck `json:"checks"`
	SimulatedAt string                `json:"simulated_at"`
}

// rotationDryRunCheck mirrors core.DryRunCheck.
type rotationDryRunCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

var rotationSimulateCmd = &cobra.Command{
	Use:   "rotation-simulate",
	Short: "Simulate a rotation dry-run for a secret (ADR-047)",
	Long: `Validate a secret's rotation configuration without executing any live rotation.

Checks:
  policy_exists  — at least one active rotation policy covers the secret
  backend_known  — the configured RotationBackend is registered in the manager
  ref_non_empty  — the RotationRef is non-empty
  ref_valid      — the RotationRef passes metacharacter validation

Requires secrets.read at the secret's scope.

Example:
  keyorix secret rotation-simulate --id 42`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if rotationSimulateID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runRotationSimulate(context.Background(), c, rotationSimulateID)
	},
}

func init() {
	rotationSimulateCmd.Flags().UintVar(&rotationSimulateID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(rotationSimulateCmd)
}

// runRotationSimulate calls the simulate API and prints the result table.
func runRotationSimulate(ctx context.Context, c *common.RemoteClient, secretID uint) error {
	var result rotationDryRunResult
	path := fmt.Sprintf("/api/v1/secrets/%d/rotation/simulate", secretID)
	if err := c.Post(ctx, path, nil, &result); err != nil {
		return err
	}
	printDryRunResult(&result)
	return nil
}

// printDryRunResult prints the check table and overall status.
func printDryRunResult(r *rotationDryRunResult) {
	fmt.Printf("Secret: %s (id %d)\n", r.SecretName, r.SecretID)
	fmt.Printf("Backend: %s   Ref: %s\n", r.Backend, r.Ref)
	fmt.Println()
	fmt.Printf("%-20s %-6s %s\n", "CHECK", "RESULT", "MESSAGE")
	fmt.Printf("%-20s %-6s %s\n", "--------------------", "------", "-------")
	for _, ch := range r.Checks {
		result := "PASS"
		if !ch.Passed {
			result = "FAIL"
		}
		fmt.Printf("%-20s %-6s %s\n", ch.Name, result, ch.Message)
	}
	fmt.Println()
	if r.Valid {
		fmt.Println("Overall: PASS — rotation configuration is valid.")
	} else {
		fmt.Println("Overall: FAIL — one or more checks failed.")
	}
}
