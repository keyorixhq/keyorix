// scan.go — Cobra command, runScan, and scan domain types/patterns/constants.
//
// For per-file-type scanning see scan_files.go.
// For report output and helpers see scan_report.go.
package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for secrets and hardcoded credentials",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

var scanImport bool
var scanReport string
var scanEnvID uint
var scanSeverity string
var scanStaged bool
var scanCommit string

func init() {
	scanCmd.Flags().BoolVar(&scanImport, "import", false, "Import found secrets into Keyorix after scanning")
	scanCmd.Flags().StringVar(&scanReport, "report", "", "Save scan report to file (JSON format)")
	scanCmd.Flags().UintVar(&scanEnvID, "env-id", 1, "Environment ID for import (1=production, 2=staging, 3=development)")
	scanCmd.Flags().StringVar(&scanSeverity, "severity", "", "Filter by severity: low, medium, high")
	scanCmd.Flags().BoolVar(&scanStaged, "staged", false, "Scan only git staged files")
	scanCmd.Flags().StringVar(&scanCommit, "commit", "", "Scan files changed in a specific commit (e.g. HEAD~1)")
	SecretCmd.AddCommand(scanCmd)
}

// ScanFinding represents a single discovered secret.
type ScanFinding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	RiskLevel  string `json:"risk_level"`
	RiskReason string `json:"risk_reason"`
	Source     string `json:"source"`
}

// ScanReport is the full scan output.
type ScanReport struct {
	ScannedPath string        `json:"scanned_path"`
	TotalFound  int           `json:"total_found"`
	HighRisk    int           `json:"high_risk"`
	MediumRisk  int           `json:"medium_risk"`
	LowRisk     int           `json:"low_risk"`
	Findings    []ScanFinding `json:"findings"`
}

// secretPatterns — common secret formats in source code and config files.
var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
	risk    string
	reason  string
}{
	{"AWS Access Key", regexp.MustCompile(`(?i)(aws_access_key_id|aws_access_key)\s*[=:]\s*["']?([A-Z0-9]{20})["']?`), "high", "AWS credential — full account access if leaked"},
	{"AWS Secret Key", regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`), "high", "AWS secret key — full account access if leaked"},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,64})["']?`), "high", "API key hardcoded in source — visible in git history"},
	{"Database Password", regexp.MustCompile(`(?i)(db[_-]?pass(word)?|database[_-]?pass(word)?|db[_-]?pwd)\s*[=:]\s*["']?([^\s"']{6,})["']?`), "high", "Database password — direct data access if leaked"},
	{"Generic Password", regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[=:]\s*["']([^\s"']{6,})["']`), "medium", "Password or secret value hardcoded"},
	{"JWT Secret", regexp.MustCompile(`(?i)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?`), "high", "JWT signing secret — allows token forgery if leaked"},
	{"Private Key Header", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`), "high", "Private key — cryptographic identity compromise"},
	{"Stripe Key", regexp.MustCompile(`(sk_live_|sk_test_)[A-Za-z0-9]{24,}`), "high", "Stripe API key — financial transactions access"},
	{"GitHub Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`), "high", "GitHub personal access token"},
	{"Generic Secret", regexp.MustCompile(`(?i)(secret|token|key|auth)\s*[=:]\s*["']([A-Za-z0-9_\-+/]{16,64})["']`), "low", "Possible secret value — review manually"},
}

var sourceExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true,
	".rb": true, ".php": true, ".cs": true, ".cpp": true, ".c": true,
	".sh": true, ".bash": true, ".zsh": true,
}

var configExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".xml": true, ".conf": true, ".config": true, ".ini": true,
	".properties": true, ".env": true,
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".idea": true,
	"dist": true, "build": true, ".next": true, "__pycache__": true,
	"target": true, "bin": true, ".terraform": true,
	"examples": true, "demo": true,
}

func runScan(cmd *cobra.Command, args []string) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	var stagedFiles map[string]bool
	if scanStaged {
		out, err := exec.Command("git", "-C", absPath, "diff", "--cached", "--name-only").Output() // #nosec G204
		if err == nil && len(out) > 0 {
			stagedFiles = map[string]bool{}
			for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if f != "" {
					stagedFiles[filepath.Join(absPath, f)] = true
				}
			}
			fmt.Printf("Scanning %d staged files...\n\n", len(stagedFiles))
		}
	}

	if scanCommit != "" {
		out, err := exec.Command("git", "-C", absPath, "diff-tree", "--no-commit-id", "-r", "--name-only", scanCommit).Output() // #nosec G204
		if err == nil && len(out) > 0 {
			stagedFiles = map[string]bool{}
			for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if f != "" {
					stagedFiles[filepath.Join(absPath, f)] = true
				}
			}
			fmt.Printf("Scanning %d files from commit %s...\n\n", len(stagedFiles), scanCommit)
		}
	}

	fmt.Printf("🔍 Scanning %s for secrets...\n\n", absPath)
	report := &ScanReport{ScannedPath: absPath}

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if stagedFiles != nil && !stagedFiles[path] {
			return nil
		}
		if info.Size() > 1*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		relPath, _ := filepath.Rel(absPath, path)

		if strings.HasSuffix(info.Name(), "_test.go") || strings.HasSuffix(info.Name(), ".test.js") || strings.HasSuffix(info.Name(), ".spec.ts") {
			return nil
		}

		baseName := strings.ToLower(filepath.Base(path))
		if baseName == ".env" || strings.HasPrefix(baseName, ".env.") {
			report.Findings = append(report.Findings, scanEnvFile(path, relPath)...)
			return nil
		}
		if configExtensions[ext] {
			report.Findings = append(report.Findings, scanConfigFile(path, relPath)...)
		} else if sourceExtensions[ext] {
			report.Findings = append(report.Findings, scanSourceFile(path, relPath)...)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	for _, f := range report.Findings {
		switch f.RiskLevel {
		case "high":
			report.HighRisk++
		case "medium":
			report.MediumRisk++
		case "low":
			report.LowRisk++
		}
	}
	report.TotalFound = len(report.Findings)

	if scanSeverity != "" {
		filtered := []ScanFinding{}
		for _, f := range report.Findings {
			if f.RiskLevel == scanSeverity {
				filtered = append(filtered, f)
			}
		}
		report.Findings = filtered
		report.TotalFound = len(filtered)
		report.HighRisk, report.MediumRisk, report.LowRisk = 0, 0, 0
		for _, f := range filtered {
			switch f.RiskLevel {
			case "high":
				report.HighRisk++
			case "medium":
				report.MediumRisk++
			case "low":
				report.LowRisk++
			}
		}
	}

	printScanReport(report)

	if report.TotalFound > 0 {
		fmt.Println("\nNext:")
		fmt.Println("  keyorix secret explain <key-name>   Explain risk and how to fix")
		fmt.Println("  keyorix secret fix <key-name>        Fix the issue automatically")
	}

	if scanReport != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(scanReport, data, 0600); err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		fmt.Printf("\n📄 Report saved to %s\n", scanReport)
	}

	if scanImport && len(report.Findings) > 0 {
		fmt.Printf("\n📥 Importing %d secrets into Keyorix...\n", report.TotalFound)
		entries := make([]secretEntry, 0, len(report.Findings))
		seen := map[string]bool{}
		for _, f := range report.Findings {
			if f.Name == "" || f.Value == "" || seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			entries = append(entries, secretEntry{Name: f.Name, Value: f.Value})
		}
		fmt.Printf("✓ Ready to import %d unique secrets (run keyorix secret import to proceed)\n", len(entries))
	}

	return nil
}
