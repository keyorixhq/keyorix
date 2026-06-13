// Package sod provides `keyorix sod` — separation-of-duties policies and violation
// detection (ISO 27001 A.5.3 / SOX). A policy names two permissions one principal
// must not hold together; violations are the users who do. Talks to /api/v1/sod/*
// (reads need system.read, policy changes system.write).
package sod

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// SoDCmd is the `keyorix sod` command.
var SoDCmd = &cobra.Command{
	Use:   "sod",
	Short: "Separation-of-duties policies and violations (ISO 27001 A.5.3)",
	Long:  "Define toxic permission combinations and find the principals who hold both sides.",
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage separation-of-duties policies",
}

type policyView struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	PermissionA string `json:"permission_a"`
	PermissionB string `json:"permission_b"`
}

type violationView struct {
	PolicyName  string `json:"policy_name"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	PermissionA string `json:"permission_a"`
	PermissionB string `json:"permission_b"`
}

var (
	sName  string
	sDesc  string
	sPermA string
	sPermB string
	sID    int
)

var policyListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List separation-of-duties policies",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Policies []policyView `json:"policies"`
			Count    int          `json:"count"`
		}
		if err := c.Get(context.Background(), "/api/v1/sod/policies", &out); err != nil {
			return err
		}
		if out.Count == 0 {
			fmt.Println("No separation-of-duties policies defined.")
			return nil
		}
		fmt.Printf("%-5s %-26s %-22s %s\n", "ID", "NAME", "PERMISSION A", "PERMISSION B")
		for _, p := range out.Policies {
			fmt.Printf("%-5d %-26s %-22s %s\n", p.ID, truncate(p.Name, 26), p.PermissionA, p.PermissionB)
		}
		return nil
	},
}

var policyCreateCmd = &cobra.Command{
	Use:          "create",
	Short:        "Create a separation-of-duties policy (two conflicting permissions)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if sName == "" || sPermA == "" || sPermB == "" {
			return fmt.Errorf("--name, --permission-a and --permission-b are required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		body := map[string]string{"name": sName, "description": sDesc, "permission_a": sPermA, "permission_b": sPermB}
		var out struct {
			Policy policyView `json:"policy"`
		}
		if err := c.Post(context.Background(), "/api/v1/sod/policies", body, &out); err != nil {
			return err
		}
		fmt.Printf("Created SoD policy %d (%q): %s + %s must not be held together.\n", out.Policy.ID, sName, sPermA, sPermB)
		return nil
	},
}

var policyDeleteCmd = &cobra.Command{
	Use:          "delete",
	Short:        "Delete a separation-of-duties policy",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if sID <= 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if err := c.Delete(context.Background(), "/api/v1/sod/policies/"+strconv.Itoa(sID)); err != nil {
			return err
		}
		fmt.Printf("Deleted SoD policy %d.\n", sID)
		return nil
	},
}

var violationsCmd = &cobra.Command{
	Use:          "violations",
	Short:        "List principals that violate a separation-of-duties policy",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Violations []violationView `json:"violations"`
			Count      int             `json:"count"`
		}
		if err := c.Get(context.Background(), "/api/v1/sod/violations", &out); err != nil {
			return err
		}
		if out.Count == 0 {
			fmt.Println("No separation-of-duties violations.")
			return nil
		}
		fmt.Printf("%d violation(s):\n\n", out.Count)
		fmt.Printf("%-26s %-22s %-22s %s\n", "POLICY", "USER", "PERMISSION A", "PERMISSION B")
		for _, v := range out.Violations {
			user := v.Username
			if v.Email != "" {
				user = fmt.Sprintf("%s <%s>", v.Username, v.Email)
			}
			fmt.Printf("%-26s %-22s %-22s %s\n", truncate(v.PolicyName, 26), truncate(user, 22), v.PermissionA, v.PermissionB)
		}
		return nil
	},
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func init() {
	policyCreateCmd.Flags().StringVar(&sName, "name", "", "Policy name (required)")
	policyCreateCmd.Flags().StringVar(&sDesc, "description", "", "Description")
	policyCreateCmd.Flags().StringVar(&sPermA, "permission-a", "", "First permission, e.g. roles.assign (required)")
	policyCreateCmd.Flags().StringVar(&sPermB, "permission-b", "", "Second permission, e.g. secrets.delete (required)")
	policyDeleteCmd.Flags().IntVar(&sID, "id", 0, "Policy ID to delete (required)")

	policyCmd.AddCommand(policyListCmd, policyCreateCmd, policyDeleteCmd)
	SoDCmd.AddCommand(policyCmd, violationsCmd)
}
