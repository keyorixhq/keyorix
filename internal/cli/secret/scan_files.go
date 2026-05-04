// scan_files.go — Per-file-type scanning: scanEnvFile, scanConfigFile, scanSourceFile, validatePath.
//
// Each scanner reads a file and returns a slice of ScanFinding.
// Types, patterns, and the main runScan orchestrator live in scan.go.
package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validatePath ensures filePath is within basePath (no path traversal).
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
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
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
	for i, line := range strings.Split(string(content), "\n") {
		for _, p := range secretPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}
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
	for i, line := range strings.Split(string(content), "\n") {
		for _, p := range secretPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}
			name := sanitizeName(matches[1])
			value := ""
			if len(matches) >= 3 {
				value = matches[len(matches)-1]
			}
			if isPlaceholder(value) {
				continue
			}
			risk := "high"
			if p.risk == "low" {
				risk = "medium"
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
					RiskReason: p.reason + " — HARDCODED IN SOURCE CODE",
					Source:     "hardcoded",
				})
			}
		}
	}
	return findings
}
