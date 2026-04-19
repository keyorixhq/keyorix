# Internationalization (i18n) Guide

This guide explains how to configure and use the internationalization features in Keyorix.

## Overview

Keyorix supports multiple languages for its user interface, error messages, and system responses. The internationalization system allows you to:

- Configure the primary language for your deployment
- Set a fallback language for missing translations
- Switch languages at runtime (programmatically)
- Extend translations for custom messages

## Supported Languages

Keyorix currently supports the following languages:

| Language Code | Language Name | Native Name |
|---------------|---------------|-------------|
| `en` | English | English |
| `ru` | Russian | Русский |
| `es` | Spanish | Español |
| `fr` | French | Français |
| `de` | German | Deutsch |

## Configuration

### Basic Configuration

Add the locale configuration to your `keyorix.yaml` file:

```yaml
locale:
  language: "en"              # Primary language
  fallback_language: "en"     # Fallback language
```

### Configuration Options

#### `language`
- **Type**: String
- **Required**: Yes
- **Default**: "en"
- **Description**: The primary language for the application interface
- **Valid Values**: "en", "ru", "es", "fr", "de"

#### `fallback_language`
- **Type**: String
- **Required**: Yes
- **Default**: "en"
- **Description**: Language to use when translations are missing in the primary language
- **Valid Values**: "en", "ru", "es", "fr", "de"
- **Recommendation**: Use "en" for maximum compatibility

### Configuration Examples

#### English (Default)
```yaml
locale:
  language: "en"
  fallback_language: "en"
```

#### Russian with English Fallback
```yaml
locale:
  language: "ru"
  fallback_language: "en"
```

#### Spanish with English Fallback
```yaml
locale:
  language: "es"
  fallback_language: "en"
```

#### French with English Fallback
```yaml
locale:
  language: "fr"
  fallback_language: "en"
```

#### German with English Fallback
```yaml
locale:
  language: "de"
  fallback_language: "en"
```

## Translation Coverage

The internationalization system covers the following areas:

### Error Messages
- Authentication errors
- Authorization errors
- Validation errors
- Database errors
- Encryption/decryption errors
- Secret management errors

### Success Messages
- Secret creation confirmations
- Update confirmations
- Deletion confirmations
- User management confirmations

### User Interface Labels
- Form field labels
- Navigation elements
- Status indicators
- Metadata labels

### Button Text
- Action buttons (Create, Update, Delete, etc.)
- Navigation buttons (Back, Next, etc.)
- Confirmation buttons (Confirm, Cancel, etc.)

## Validation

### Configuration Validation

The system validates locale configuration at startup:

1. **Required Fields**: Both `language` and `fallback_language` must be specified
2. **Valid Language Codes**: Only supported language codes are accepted
3. **Fallback Logic**: If invalid codes are provided, the system defaults to English

### Translation Validation

Use the built-in validation utility to check translation completeness:

```bash
# Validate all translations
go run cmd/validate-translations/main.go

# Validate translations in a specific directory
go run cmd/validate-translations/main.go /path/to/locales
```

The validation utility checks for:
- Missing translations across languages
- Empty translation values
- Inconsistent message keys
- JSON syntax errors

## Development

### Adding New Messages

1. **Add to English**: Add new message keys to `internal/i18n/locales/en.json`
2. **Translate**: Add corresponding translations to all other language files
3. **Use in Code**: Reference the message key in your Go code:

```go
import "github.com/keyorixhq/keyorix/internal/i18n"

// Simple translation
message := i18n.T("YourMessageKey", nil)

// Translation with template data
message := i18n.T("YourMessageKey", map[string]interface{}{
    "Name": "John",
    "Count": 5,
})
```

### Message Key Conventions

Follow these naming conventions for message keys:

- **Errors**: `Error*` (e.g., `ErrorUserNotFound`)
- **Success**: `Success*` (e.g., `SuccessSecretCreated`)
- **Info**: `Info*` (e.g., `InfoSecretExpired`)
- **Labels**: `Label*` (e.g., `LabelName`)
- **Buttons**: `Button*` (e.g., `ButtonCreate`)

### Translation File Format

Translation files use JSON format with the following structure:

```json
{
  "MessageKey": {
    "description": "Human-readable description of the message",
    "one": "Singular form of the message",
    "other": "Plural form of the message"
  }
}
```

Example:
```json
{
  "Welcome": {
    "description": "Welcome message for new users",
    "one": "Welcome to Keyorix!",
    "other": "Welcome to Keyorix!"
  },
  "ErrorUserNotFound": {
    "description": "Error when user cannot be found",
    "one": "User not found",
    "other": "User not found"
  }
}
```

## Runtime Language Switching

### Programmatic Language Switching

```go
import "github.com/keyorixhq/keyorix/internal/i18n"

// Get the current localizer
localizer := i18n.GetLocalizer()

// Switch to a different language
localizer.SetLanguage("ru")

// Use translations in the new language
message := localizer.Localize("Welcome", nil)
```

### Thread Safety

The internationalization system is thread-safe and supports concurrent access:
- Multiple goroutines can safely call translation functions
- Language switching is protected by mutexes
- No additional synchronization is required in your code

## Troubleshooting

### Common Issues

#### 1. Application Fails to Start
**Error**: "unsupported language: xx"
**Solution**: Check that your language codes in `keyorix.yaml` are valid

#### 2. Messages Appear in English Despite Configuration
**Possible Causes**:
- Translation file is missing or corrupted
- Message key doesn't exist in the target language
- Fallback to English is working as designed

**Solution**: Run the validation utility to check translation completeness

#### 3. Mixed Languages in Output
**Cause**: Some message keys are missing in the primary language
**Solution**: Add missing translations or check the validation report

### Debugging

Enable debug logging to see i18n system initialization:

```yaml
logging:
  level: "debug"
```

Look for log messages like:
```
i18n system initialized with language: ru, fallback: en
```

### Validation Commands

```bash
# Basic validation
go run cmd/validate-translations/main.go

# Detailed validation with custom directory
go run cmd/validate-translations/main.go ./custom/locales

# Help
go run cmd/validate-translations/main.go --help
```

## Best Practices

### Configuration
1. Always use English ("en") as the fallback language
2. Test your configuration with the validation utility
3. Keep language codes consistent across environments

### Development
1. Add English translations first, then translate to other languages
2. Use descriptive message keys that indicate their purpose
3. Include context in the "description" field of translation files
4. Validate translations before deploying

### Deployment
1. Validate all translations in your CI/CD pipeline
2. Test language switching in staging environments
3. Monitor for missing translation warnings in logs

## Performance Considerations

### Startup Performance
- Translation files are loaded once at startup
- All languages are loaded into memory for fast access
- Embedded files eliminate file I/O during runtime

### Runtime Performance
- Translation lookups are O(1) hash table operations
- Language switching creates a new localizer instance
- Thread-safe operations use read-write mutexes for optimal performance

### Memory Usage
- All translation files are kept in memory
- Memory usage scales with the number of supported languages
- Typical memory overhead: ~1-2MB for all supported languages

## Contributing Translations

To contribute new translations or improve existing ones:

1. Fork the repository
2. Add or update translation files in `internal/i18n/locales/`
3. Run the validation utility to ensure completeness
4. Test your translations with the application
5. Submit a pull request with your changes

### Translation Guidelines
- Maintain consistent terminology across messages
- Consider cultural context, not just literal translation
- Keep message length appropriate for UI constraints
- Test translations in the actual application interface