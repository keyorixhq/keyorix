package secret

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix <key-name>",
	Short: "Fix a hardcoded secret by moving it to an environment variable",
	Args:  cobra.ExactArgs(1),
	RunE:  runFix,
}

var fixDryRun bool
var fixAll bool
var fixInteractive bool
var fixEnvFile string
var fixPath string

func init() {
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", true, "Preview changes without applying (default: true)")
	fixCmd.Flags().BoolVar(&fixAll, "all", false, "Fix all findings from last scan")
	fixCmd.Flags().BoolVar(&fixInteractive, "interactive", false, "Step through each fix interactively")
	fixCmd.Flags().StringVar(&fixEnvFile, "env-file", ".env", "Target .env file for extracted secrets")
	fixCmd.Flags().StringVar(&fixPath, "path", ".", "Path to scan for the secret")
	SecretCmd.AddCommand(fixCmd)
}

type fixPlan struct {
	File         string
	Line         int
	OriginalLine string
	NewLine      string
	EnvVarName   string
	SecretValue  string
}

func runFix(cmd *cobra.Command, args []string) error {
	keyName := args[0]
	envVarName := strings.ToUpper(strings.ReplaceAll(keyName, "-", "_"))

	absPath, err := filepath.Abs(fixPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	fmt.Printf("Analysing %s...\n\n", keyName)

	// Find all occurrences
	plans, err := findAndPlanFix(absPath, envVarName)
	if err != nil {
		return err
	}

	if len(plans) == 0 {
		fmt.Printf("No hardcoded occurrences of %s found in %s\n", keyName, absPath)
		fmt.Printf("\nIf the secret is in a .env file, it is already in the right place.\n")
		fmt.Printf("Store it in Keyorix:\n")
		fmt.Printf("  keyorix secret create %s --value <value>\n", strings.ToLower(keyName))
		return nil
	}

	// Show plan
	fmt.Printf("Fix plan for %s:\n\n", keyName)
	for _, plan := range plans {
		fmt.Printf("  File: %s (line %d)\n", plan.File, plan.Line)
		fmt.Printf("  Before: %s\n", strings.TrimSpace(plan.OriginalLine))
		fmt.Printf("  After:  %s\n", strings.TrimSpace(plan.NewLine))
		fmt.Println()
	}

	// Show .env addition
	fmt.Printf("  Add to %s:\n", fixEnvFile)
	fmt.Printf("  %s=<your-value-here>\n\n", envVarName)

	if fixDryRun && !fixInteractive {
		fmt.Println("Dry run — no changes made.")
		fmt.Printf("\nTo apply: keyorix secret fix %s --dry-run=false\n", keyName)
		fmt.Printf("To review interactively: keyorix secret fix %s --interactive\n", keyName)
		return nil
	}

	if fixInteractive {
		fmt.Printf("Apply these changes? (y/n): ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Apply fixes
	for _, plan := range plans {
		if err := applyFix(plan); err != nil {
			fmt.Printf("Error fixing %s: %v\n", plan.File, err)
			continue
		}
		fmt.Printf("Fixed %s:%d\n", plan.File, plan.Line)
	}

	// Append to .env file
	envPath := filepath.Join(absPath, fixEnvFile)
	f, err := os.OpenFile(envPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
	if err == nil {
		fmt.Fprintf(f, "\n# Added by keyorix fix\n%s=\n", envVarName) // #nosec G104
		f.Close()                                                     // #nosec G104
		fmt.Printf("Added %s= to %s (fill in the value)\n", envVarName, fixEnvFile)
	}

	fmt.Printf("\nDone. Next steps:\n")
	fmt.Printf("  1. Fill in the value in %s\n", fixEnvFile)
	fmt.Printf("  2. Add %s to .gitignore\n", fixEnvFile)
	fmt.Printf("  3. Store in Keyorix: keyorix secret create %s --value <value>\n", strings.ToLower(keyName))
	fmt.Printf("  4. Run with injection: keyorix run --env production -- your-app\n")

	return nil
}

func findAndPlanFix(basePath, envVarName string) ([]fixPlan, error) {
	var plans []fixPlan
	pattern := regexp.MustCompile(`(?i)(` + regexp.QuoteMeta(strings.ToLower(envVarName)) + `|` + regexp.QuoteMeta(envVarName) + `)\s*[=:]\s*["']([^"']+)["']`)

	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.IsDir() && skipDirs[info.Name()] {
			return filepath.SkipDir
		}
		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		if info.Size() > 1*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !sourceExtensions[ext] && !configExtensions[ext] {
			return nil
		}

		content, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 G122 -- path comes from filepath.Walk rooted at operator-supplied absPath; symlink TOCTOU acceptable for a local developer tool
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(basePath, path)
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) >= 3 {
				value := matches[2]
				if isPlaceholder(value) {
					continue
				}
				// Generate replacement line
				newLine := pattern.ReplaceAllString(line,
					matches[1]+"=os.getenv(\""+envVarName+"\")")
				plans = append(plans, fixPlan{
					File:         relPath,
					Line:         i + 1,
					OriginalLine: line,
					NewLine:      newLine,
					EnvVarName:   envVarName,
					SecretValue:  value,
				})
			}
		}
		return nil
	})
	return plans, err
}

func applyFix(plan fixPlan) error {
	content, err := os.ReadFile(filepath.Clean(plan.File)) // #nosec G304 G122 -- path sourced from filepath.Walk within operator-controlled basePath
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	if plan.Line-1 >= len(lines) {
		return fmt.Errorf("line %d out of range", plan.Line)
	}
	lines[plan.Line-1] = plan.NewLine
	return os.WriteFile(plan.File, []byte(strings.Join(lines, "\n")), 0600) // #nosec G703 -- plan.File is a relative path from filepath.Walk within operator-supplied basePath; path traversal not a realistic threat for this local CLI tool
}
