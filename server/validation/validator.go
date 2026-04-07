package validation

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/utils/safeconv"
)

// Validator provides request validation functionality
type Validator struct {
	errors map[string][]string
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		errors: make(map[string][]string),
	}
}

// ValidationError represents validation errors
type ValidationError struct {
	Field   string      `json:"field"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

func (ve ValidationErrors) Error() string {
	var messages []string
	for _, err := range ve.Errors {
		messages = append(messages, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(messages, "; ")
}

// Validate validates a struct using reflection and validation tags
func (v *Validator) Validate(s interface{}) error {
	v.errors = make(map[string][]string)

	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("validation target must be a struct")
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Get validation tag
		tag := fieldType.Tag.Get("validate")
		if tag == "" {
			continue
		}

		// Get JSON field name for error reporting
		jsonTag := fieldType.Tag.Get("json")
		fieldName := fieldType.Name
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" && parts[0] != "-" {
				fieldName = parts[0]
			}
		}

		// Validate field
		v.validateField(fieldName, field, tag)
	}

	if len(v.errors) > 0 {
		var validationErrors []ValidationError
		for field, messages := range v.errors {
			for _, message := range messages {
				validationErrors = append(validationErrors, ValidationError{
					Field:   field,
					Message: message,
				})
			}
		}
		return ValidationErrors{Errors: validationErrors}
	}

	return nil
}

// validateField validates a single field based on validation rules
func (v *Validator) validateField(fieldName string, field reflect.Value, tag string) {
	rules := strings.Split(tag, ",")

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		// Handle optional fields
		if rule == "omitempty" && v.isEmpty(field) {
			return
		}

		// Parse rule and parameters
		parts := strings.Split(rule, "=")
		ruleName := parts[0]
		var param string
		if len(parts) > 1 {
			param = parts[1]
		}

		// Apply validation rule
		if err := v.applyRule(fieldName, field, ruleName, param); err != nil {
			v.addError(fieldName, err.Error())
		}
	}
}

// applyRule applies a specific validation rule
func (v *Validator) applyRule(fieldName string, field reflect.Value, ruleName, param string) error {
	switch ruleName {
	case "required":
		if v.isEmpty(field) {
			return fmt.Errorf("%s", i18n.T("ErrorValidation", nil))
		}
	case "min":
		return v.validateMin(field, param)
	case "max":
		return v.validateMax(field, param)
	case "email":
		return v.validateEmail(field)
	case "url":
		return v.validateURL(field)
	case "alpha":
		return v.validateAlpha(field)
	case "alphanum":
		return v.validateAlphaNum(field)
	case "numeric":
		return v.validateNumeric(field)
	case "oneof":
		return v.validateOneOf(field, param)
	}

	return nil
}

// isEmpty checks if a field is empty
func (v *Validator) isEmpty(field reflect.Value) bool {
	switch field.Kind() {
	case reflect.String:
		return field.String() == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return field.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return field.IsNil()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return field.Float() == 0
	case reflect.Bool:
		return !field.Bool()
	}
	return false
}

// validateMin validates minimum length/value
func (v *Validator) validateMin(field reflect.Value, param string) error {
	var min int
	_, _ = fmt.Sscanf(param, "%d", &min)

	switch field.Kind() {
	case reflect.String:
		if len(field.String()) < min {
			return fmt.Errorf("must be at least %d characters", min)
		}
	case reflect.Slice, reflect.Array:
		if field.Len() < min {
			return fmt.Errorf("must have at least %d items", min)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < int64(min) {
			return fmt.Errorf("must be at least %d", min)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		minUint64, err := safeconv.IntToUint64(min)
		if err != nil {
			return fmt.Errorf("invalid min value: %v", err)
		}
		if field.Uint() < minUint64 {
			return fmt.Errorf("must be at least %d", min)
		}
	}

	return nil
}

// validateMax validates maximum length/value
func (v *Validator) validateMax(field reflect.Value, param string) error {
	var max int
	_, _ = fmt.Sscanf(param, "%d", &max)

	switch field.Kind() {
	case reflect.String:
		if len(field.String()) > max {
			return fmt.Errorf("must be at most %d characters", max)
		}
	case reflect.Slice, reflect.Array:
		if field.Len() > max {
			return fmt.Errorf("must have at most %d items", max)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() > int64(max) {
			return fmt.Errorf("must be at most %d", max)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		maxUint64, err := safeconv.IntToUint64(max)
		if err != nil {
			return fmt.Errorf("invalid max value: %v", err)
		}
		if field.Uint() > maxUint64 {
			return fmt.Errorf("must be at most %d", max)
		}
	}

	return nil
}

// validateEmail validates email format
func (v *Validator) validateEmail(field reflect.Value) error {
	if field.Kind() != reflect.String {
		return nil
	}

	email := field.String()
	if email == "" {
		return nil
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelEmail", nil))
	}

	return nil
}

// validateURL validates URL format
func (v *Validator) validateURL(field reflect.Value) error {
	if field.Kind() != reflect.String {
		return nil
	}

	url := field.String()
	if url == "" {
		return nil
	}

	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	if !urlRegex.MatchString(url) {
		return fmt.Errorf("%s: must be a valid URL", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// validateAlpha validates alphabetic characters only
func (v *Validator) validateAlpha(field reflect.Value) error {
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	alphaRegex := regexp.MustCompile(`^[a-zA-Z]+$`)
	if !alphaRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only alphabetic characters", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// validateAlphaNum validates alphanumeric characters only
func (v *Validator) validateAlphaNum(field reflect.Value) error {
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	alphaNumRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !alphaNumRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only alphanumeric characters", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// validateNumeric validates numeric characters only
func (v *Validator) validateNumeric(field reflect.Value) error {
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	numericRegex := regexp.MustCompile(`^[0-9]+$`)
	if !numericRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only numeric characters", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// validateOneOf validates that value is one of allowed values
func (v *Validator) validateOneOf(field reflect.Value, param string) error {
	if field.Kind() != reflect.String {
		return nil
	}

	value := field.String()
	if value == "" {
		return nil
	}

	allowedValues := strings.Split(param, " ")
	for _, allowed := range allowedValues {
		if value == allowed {
			return nil
		}
	}

	return fmt.Errorf("%s: must be one of: %s", i18n.T("ErrorValidation", nil), strings.Join(allowedValues, ", "))
}

// addError adds a validation error
func (v *Validator) addError(field, message string) {
	if v.errors[field] == nil {
		v.errors[field] = []string{}
	}
	v.errors[field] = append(v.errors[field], message)
}
