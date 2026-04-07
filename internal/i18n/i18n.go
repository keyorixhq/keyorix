package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/keyorixhq/keyorix/internal/config"
	"golang.org/x/text/language"
)

// Embed the locales directory
//
//go:embed locales/*.json
var localeFS embed.FS

// Localizer provides translation functionality
type Localizer struct {
	bundle       *i18n.Bundle
	localizer    *i18n.Localizer
	currentLang  string
	fallbackLang string
	mutex        sync.RWMutex
}

// Global instance of the localizer
var globalLocalizer *Localizer
var once sync.Once

// InitializeForTesting sets up the i18n system with default config for testing
func InitializeForTesting() error {
	defaultConfig := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	return Initialize(defaultConfig)
}

// Initialize sets up the i18n system with the provided config
func Initialize(cfg *config.Config) error {
	var initErr error
	once.Do(func() {
		globalLocalizer = &Localizer{
			bundle:       i18n.NewBundle(language.English),
			currentLang:  cfg.Locale.Language,
			fallbackLang: cfg.Locale.FallbackLanguage,
		}

		// If no language is specified, use English
		if globalLocalizer.currentLang == "" {
			globalLocalizer.currentLang = "en"
		}

		// If no fallback language is specified, use English
		if globalLocalizer.fallbackLang == "" {
			globalLocalizer.fallbackLang = "en"
		}

		// Configure the bundle
		globalLocalizer.bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

		// Load all translation files
		if err := loadTranslationFiles(globalLocalizer.bundle); err != nil {
			initErr = fmt.Errorf("error loading translation files: %w", err)
			return
		}

		// Create the localizer with the current language and fallback
		globalLocalizer.localizer = i18n.NewLocalizer(
			globalLocalizer.bundle,
			globalLocalizer.currentLang,
			globalLocalizer.fallbackLang,
		)
	})

	return initErr
}

// loadTranslationFiles loads all translation files from the embedded filesystem
func loadTranslationFiles(bundle *i18n.Bundle) error {
	entries, err := fs.ReadDir(localeFS, "locales")
	if err != nil {
		return fmt.Errorf("failed to read locales directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join("locales", entry.Name())
		data, err := localeFS.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read translation file %s: %w", filePath, err)
		}

		if _, err := bundle.ParseMessageFileBytes(data, filePath); err != nil {
			return fmt.Errorf("failed to parse translation file %s: %w", filePath, err)
		}
	}

	return nil
}

// GetLocalizer returns the global localizer instance
func GetLocalizer() *Localizer {
	if globalLocalizer == nil {
		panic("i18n not initialized, call Initialize() first")
	}
	return globalLocalizer
}

// SetLanguage changes the current language
func (l *Localizer) SetLanguage(lang string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.currentLang = lang
	l.localizer = i18n.NewLocalizer(l.bundle, l.currentLang, l.fallbackLang)
}

// Localize translates a message ID with optional template data
func (l *Localizer) Localize(messageID string, templateData map[string]interface{}) string {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	msg, err := l.localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    messageID,
		TemplateData: templateData,
	})

	if err != nil {
		// If translation fails, return the message ID as fallback
		return messageID
	}

	return msg
}

// MustLocalize is like Localize but panics if the message is not found
func (l *Localizer) MustLocalize(messageID string, templateData map[string]interface{}) string {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	msg, err := l.localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    messageID,
		TemplateData: templateData,
	})

	if err != nil {
		panic(fmt.Sprintf("missing translation for message ID: %s", messageID))
	}

	return msg
}

// T is a shorthand for Localize
func T(messageID string, templateData map[string]interface{}) string {
	return GetLocalizer().Localize(messageID, templateData)
}

// MustT is a shorthand for MustLocalize
func MustT(messageID string, templateData map[string]interface{}) string {
	return GetLocalizer().MustLocalize(messageID, templateData)
}

// ResetForTesting resets the global i18n state for testing purposes
func ResetForTesting() {
	globalLocalizer = nil
	once = sync.Once{}
}
