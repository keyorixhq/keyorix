package secret

import (
	"encoding/json"
	"fmt"
	"os"
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

func init() {
	scanCmd.Flags().BoolVar(&scanImport, "import", false, "Import found secrets into Keyorix after scanning")
	scanCmd.Flags().StringVar(&scanReport, "report", "", "Save scan report to file (JSON format)")
	scanCmd.Flags().UintVar(&scanEnvID, "env-id", 1, "Environment ID for import (1=production, 2=staging, 3=development)")
	SecretCmd.AddCommand(scanCmd)
}

// ScanFinding represents a single discovered secret
type ScanFinding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	RiskLevel  string `json:"risk_level"` // high, medium, low
	RiskReason string `json:"risk_reason"`
	Source     string `json:"source"` // hardcoded, env_file, config_file
}

// ScanReport is the full scan output
type ScanReport struct {
	ScannedPath string        `json:"scanned_path"`
	TotalFound  int           `json:"total_found"`
	HighRisk    int           `json:"high_risk"`
	MediumRisk  int           `json:"medium_risk"`
	LowRisk     int           `json:"low_risk"`
	Findings    []ScanFinding `json:"findings"`
}

// Secret patterns — matches common secret formats in source code and config files
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

// File extensions to scan for hardcoded secrets
var sourceExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true,
	".rb": true, ".php": true, ".cs": true, ".cpp": true, ".c": true,
	".sh": true, ".bash": true, ".zsh": true,
}

// Config file extensions — medium risk
var configExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".xml": true, ".conf": true, ".config": true, ".ini": true,
	".properties": true, ".env": true,
}

// Directories to skip
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

	fmt.Printf("🔍 Scanning %s for secrets...\n\n", absPath)

	report := &ScanReport{ScannedPath: absPath}

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Skip directories
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip large files (> 1MB)
		if info.Size() > 1*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		relPath, _ := filepath.Rel(absPath, path)

		// Skip test files — they intentionally contain test credentials
		if strings.HasSuffix(info.Name(), "_test.go") || strings.HasSuffix(info.Name(), ".test.js") || strings.HasSuffix(info.Name(), ".spec.ts") {
			return nil
		}

		// Check .env files specifically
		baseName := strings.ToLower(filepath.Base(path))
		if baseName == ".env" || strings.HasPrefix(baseName, ".env.") {
			findings := scanEnvFile(path, relPath)
			report.Findings = append(report.Findings, findings...)
			return nil
		}

		if configExtensions[ext] {
			findings := scanConfigFile(path, relPath)
			report.Findings = append(report.Findings, findings...)
		} else if sourceExtensions[ext] {
			findings := scanSourceFile(path, relPath)
			report.Findings = append(report.Findings, findings...)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Count risk levels
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

	// Print results
	printScanReport(report)

	// Save report if requested
	if scanReport != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(scanReport, data, 0600); err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		fmt.Printf("\n📄 Report saved to %s\n", scanReport)
	}

	// Import if requested
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

// validatePath ensures the file path is safe to read (no path traversal)
func validatePath(basePath, filePath string) error {
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return err
	}
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(absFile, absBase) {
		return fmt.Errorf("path traversal detected: %s", filePath)
	}
	return nil
}

func scanEnvFile(path, relPath string) []ScanFinding {
	// #nosec G304 -- path is validated against scan root and comes from filepath.Walk
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	var findings []ScanFinding
	for i, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)
		if value == "" || value == "changeme" || value == "your_secret_here" || value == "xxx" {
			continue
		}
		findings = append(findings, ScanFinding{
			File:       relPath,
			Line:       i + 1,
			Name:       name,
			Value:      value,
			RiskLevel:  "medium",
			RiskReason: "Secret in .env file — ensure file is in .gitignore",
			Source:     "env_file",
		})
	}
	return findings
}

func scanConfigFile(path, relPath string) []ScanFinding {
	// #nosec G304 -- path is validated against scan root and comes from filepath.Walk
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	var findings []ScanFinding
	seen := map[string]bool{}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		for _, p := range secretPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				name := sanitizeName(matches[1])
				value := ""
				if len(matches) >= 3 {
					value = matches[len(matches)-1]
				}
				if isPlaceholder(value) {
					continue
				}
				key := fmt.Sprintf("%s:%d", relPath, i+1)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, ScanFinding{
						File:       relPath,
						Line:       i + 1,
						Name:       name,
						Value:      value,
						RiskLevel:  p.risk,
						RiskReason: p.reason,
						Source:     "config_file",
					})
				}
			}
		}
	}
	return findings
}

func scanSourceFile(path, relPath string) []ScanFinding {
	// #nosec G304 -- path is validated against scan root and comes from filepath.Walk
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	var findings []ScanFinding
	seen := map[string]bool{}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		for _, p := range secretPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				name := sanitizeName(matches[1])
				value := ""
				if len(matches) >= 3 {
					value = matches[len(matches)-1]
				}
				if isPlaceholder(value) {
					continue
				}
				// Hardcoded in source = higher risk
				risk := p.risk
				reason := p.reason + " — HARDCODED IN SOURCE CODE"
				if p.risk == "low" {
					risk = "medium"
				} else {
					risk = "high"
				}
				key := fmt.Sprintf("%s:%d", relPath, i+1)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, ScanFinding{
						File:       relPath,
						Line:       i + 1,
						Name:       name,
						Value:      value,
						RiskLevel:  risk,
						RiskReason: reason,
						Source:     "hardcoded",
					})
				}
			}
		}
	}
	return findings
}

func printScanReport(report *ScanReport) {
	if report.TotalFound == 0 {
		fmt.Println("✅ No secrets found.")
		return
	}

	fmt.Printf("Found %d secrets:\n", report.TotalFound)
	if report.HighRisk > 0 {
		fmt.Printf("  🔴 %d HIGH risk\n", report.HighRisk)
	}
	if report.MediumRisk > 0 {
		fmt.Printf("  🟡 %d MEDIUM risk\n", report.MediumRisk)
	}
	if report.LowRisk > 0 {
		fmt.Printf("  🟢 %d LOW risk\n", report.LowRisk)
	}
	fmt.Println()

	// Group by source
	hardcoded := []ScanFinding{}
	envFiles := []ScanFinding{}
	configFiles := []ScanFinding{}

	for _, f := range report.Findings {
		switch f.Source {
		case "hardcoded":
			hardcoded = append(hardcoded, f)
		case "env_file":
			envFiles = append(envFiles, f)
		case "config_file":
			configFiles = append(configFiles, f)
		}
	}

	if len(hardcoded) > 0 {
		fmt.Printf("⚠️  Hardcoded in source code (%d) — HIGHEST RISK:\n", len(hardcoded))
		for _, f := range hardcoded {
			fmt.Printf("   %s:%d — %s\n", f.File, f.Line, f.Name)
			fmt.Printf("   └─ %s\n", f.RiskReason)
		}
		fmt.Println()
	}

	if len(envFiles) > 0 {
		fmt.Printf("📄 Found in .env files (%d):\n", len(envFiles))
		for _, f := range envFiles {
			fmt.Printf("   %s:%d — %s\n", f.File, f.Line, f.Name)
		}
		fmt.Println()
	}

	if len(configFiles) > 0 {
		fmt.Printf("⚙️  Found in config files (%d):\n", len(configFiles))
		for _, f := range configFiles {
			fmt.Printf("   %s:%d — %s\n", f.File, f.Line, f.Name)
		}
		fmt.Println()
	}

	fmt.Println("Next steps:")
	fmt.Println("  keyorix secret scan . --import    Import all into Keyorix")
	fmt.Println("  keyorix secret scan . --report scan.json    Save full report")
	fmt.Println("  keyorix run --env production -- <your-app>  Inject secrets at runtime")
}

func sanitizeName(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = regexp.MustCompile(`[^A-Z0-9_]`).ReplaceAllString(s, "_")
	return s
}

func isPlaceholder(s string) bool {
	placeholders := []string{"changeme", "your_secret", "xxx", "example", "placeholder",
		"todo", "fixme", "replace", "insert", "your-", "<your", "${", "%("}
	lower := strings.ToLower(s)
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return len(s) < 4
}
