package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

type TranslationMessage struct {
	Description string `json:"description"`
	One         string `json:"one"`
	Other       string `json:"other"`
}

type TranslationFile map[string]TranslationMessage

type ValidationResult struct {
	Language        string
	FilePath        string
	MessageCount    int
	MissingMessages []string
	EmptyMessages   []string
	Valid           bool
}

type ValidationSummary struct {
	TotalLanguages   int
	ValidLanguages   int
	InvalidLanguages int
	Results          []ValidationResult
	AllMessageIDs    []string
	InconsistentKeys []string
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printUsage()
		return
	}

	localesDir := "internal/i18n/locales"
	if len(os.Args) > 1 {
		localesDir = os.Args[1]
	}

	fmt.Println("🌍 Translation Validation Utility")
	fmt.Println("==================================")
	fmt.Printf("Validating translations in: %s\n\n", localesDir)

	summary, err := validateTranslations(localesDir)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}

	printValidationSummary(summary)

	if summary.InvalidLanguages > 0 {
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Translation Validation Utility")
	fmt.Println("Usage: validate-translations [locales-directory]")
	fmt.Println("")
	fmt.Println("Arguments:")
	fmt.Println("  locales-directory  Path to the locales directory (default: internal/i18n/locales)")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  validate-translations")
	fmt.Println("  validate-translations ./locales")
	fmt.Println("  validate-translations /path/to/translations")
}

func validateTranslations(localesDir string) (*ValidationSummary, error) {
	if _, err := os.Stat(localesDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("locales directory does not exist: %s", localesDir)
	}

	files, err := os.ReadDir(localesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read locales directory: %w", err)
	}

	var translationFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			translationFiles = append(translationFiles, file.Name())
		}
	}

	if len(translationFiles) == 0 {
		return nil, fmt.Errorf("no translation files found in %s", localesDir)
	}

	translations := make(map[string]TranslationFile)
	allMessageIDs := make(map[string]bool)

	for _, filename := range translationFiles {
		lang := strings.TrimSuffix(filename, ".json")
		filePath := filepath.Join(localesDir, filename)

		translationFile, err := loadTranslationFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", filename, err)
		}

		translations[lang] = translationFile

		for messageID := range translationFile {
			allMessageIDs[messageID] = true
		}
	}

	var sortedMessageIDs []string
	for messageID := range allMessageIDs {
		sortedMessageIDs = append(sortedMessageIDs, messageID)
	}
	sort.Strings(sortedMessageIDs)

	var results []ValidationResult
	validLanguages := 0
	invalidLanguages := 0

	for _, filename := range translationFiles {
		lang := strings.TrimSuffix(filename, ".json")
		filePath := filepath.Join(localesDir, filename)
		result := validateLanguage(lang, filePath, translations[lang], sortedMessageIDs)
		results = append(results, result)

		if result.Valid {
			validLanguages++
		} else {
			invalidLanguages++
		}
	}

	inconsistentKeys := findInconsistentKeys(translations, sortedMessageIDs)

	summary := &ValidationSummary{
		TotalLanguages:   len(translationFiles),
		ValidLanguages:   validLanguages,
		InvalidLanguages: invalidLanguages,
		Results:          results,
		AllMessageIDs:    sortedMessageIDs,
		InconsistentKeys: inconsistentKeys,
	}

	return summary, nil
}

func loadTranslationFile(filePath string) (TranslationFile, error) {
	// Use secure file reading with base directory validation
	baseDir := "internal/i18n/locales"
	data, err := securefiles.SafeReadFile(baseDir, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file securely: %w", err)
	}

	var translationFile TranslationFile
	if err := json.Unmarshal(data, &translationFile); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return translationFile, nil
}

func validateLanguage(lang, filePath string, translations TranslationFile, allMessageIDs []string) ValidationResult {
	result := ValidationResult{
		Language:     lang,
		FilePath:     filePath,
		MessageCount: len(translations),
		Valid:        true,
	}

	for _, messageID := range allMessageIDs {
		if _, exists := translations[messageID]; !exists {
			result.MissingMessages = append(result.MissingMessages, messageID)
			result.Valid = false
		}
	}

	for messageID, message := range translations {
		if message.One == "" && message.Other == "" {
			result.EmptyMessages = append(result.EmptyMessages, messageID)
			result.Valid = false
		}
	}

	return result
}

func findInconsistentKeys(translations map[string]TranslationFile, allMessageIDs []string) []string {
	var inconsistentKeys []string
	languageCount := len(translations)

	for _, messageID := range allMessageIDs {
		count := 0
		for _, translationFile := range translations {
			if _, exists := translationFile[messageID]; exists {
				count++
			}
		}
		if count != languageCount {
			inconsistentKeys = append(inconsistentKeys, messageID)
		}
	}

	return inconsistentKeys
}

func printValidationSummary(summary *ValidationSummary) {
	fmt.Printf("📊 Validation Summary\n")
	fmt.Printf("Total Languages: %d\n", summary.TotalLanguages)
	fmt.Printf("Valid Languages: %d\n", summary.ValidLanguages)
	fmt.Printf("Invalid Languages: %d\n", summary.InvalidLanguages)
	fmt.Printf("Total Message IDs: %d\n\n", len(summary.AllMessageIDs))

	for _, result := range summary.Results {
		if result.Valid {
			fmt.Printf("✅ %s (%d messages)\n", result.Language, result.MessageCount)
		} else {
			fmt.Printf("❌ %s (%d messages)\n", result.Language, result.MessageCount)
			if len(result.MissingMessages) > 0 {
				fmt.Printf("   Missing messages (%d):\n", len(result.MissingMessages))
				for _, messageID := range result.MissingMessages {
					fmt.Printf("     - %s\n", messageID)
				}
			}
			if len(result.EmptyMessages) > 0 {
				fmt.Printf("   Empty messages (%d):\n", len(result.EmptyMessages))
				for _, messageID := range result.EmptyMessages {
					fmt.Printf("     - %s\n", messageID)
				}
			}
		}
	}

	if len(summary.InconsistentKeys) > 0 {
		fmt.Printf("\n⚠️  Inconsistent Keys (%d):\n", len(summary.InconsistentKeys))
		fmt.Println("These message IDs don't exist in all languages:")
		for _, messageID := range summary.InconsistentKeys {
			fmt.Printf("   - %s\n", messageID)

			var hasKey []string
			var missingKey []string

			for _, result := range summary.Results {
				translations, _ := loadTranslationFile(result.FilePath)
				if _, exists := translations[messageID]; exists {
					hasKey = append(hasKey, result.Language)
				} else {
					missingKey = append(missingKey, result.Language)
				}
			}

			if len(hasKey) > 0 {
				fmt.Printf("     Present in: %s\n", strings.Join(hasKey, ", "))
			}
			if len(missingKey) > 0 {
				fmt.Printf("     Missing in: %s\n", strings.Join(missingKey, ", "))
			}
		}
	}

	fmt.Println()
	if summary.InvalidLanguages == 0 {
		fmt.Println("🎉 All translations are valid!")
	} else {
		fmt.Printf("🚨 %d language(s) have validation issues\n", summary.InvalidLanguages)
	}

	fmt.Println("\n📈 Statistics:")
	fmt.Printf("Coverage: %.1f%% (%d/%d languages valid)\n",
		float64(summary.ValidLanguages)/float64(summary.TotalLanguages)*100,
		summary.ValidLanguages, summary.TotalLanguages)

	if len(summary.InconsistentKeys) > 0 {
		fmt.Printf("Consistency: %.1f%% (%d/%d keys consistent)\n",
			float64(len(summary.AllMessageIDs)-len(summary.InconsistentKeys))/float64(len(summary.AllMessageIDs))*100,
			len(summary.AllMessageIDs)-len(summary.InconsistentKeys), len(summary.AllMessageIDs))
	} else {
		fmt.Println("Consistency: 100% (all keys consistent)")
	}
}
