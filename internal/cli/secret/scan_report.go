// scan_report.go — printScanReport, sanitizeName, isPlaceholder.
//
// Output formatting and string helpers for the scan command.
// Types and the main runScan orchestrator live in scan.go.
package secret

import (
	"fmt"
	"regexp"
	"strings"
)

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

	var hardcoded, envFiles, configFiles []ScanFinding
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
	return regexp.MustCompile(`[^A-Z0-9_]`).ReplaceAllString(s, "_")
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
