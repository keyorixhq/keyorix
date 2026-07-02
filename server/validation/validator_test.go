package validation

import (
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Several validation rules render their message via i18n.T, whose GetLocalizer
// panics when the bundle is uninitialized. Initialize it once for the package.
func TestMain(m *testing.M) {
	if err := i18n.InitializeForTesting(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestValidate_NonStructIsError(t *testing.T) {
	v := NewValidator()
	err := v.Validate("not a struct")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a struct")
}

func TestValidate_AcceptsPointerToStruct(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(&payload{Name: "ok"}))
}

func TestValidate_Required(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "present"}))

	err := v.Validate(payload{Name: ""})
	require.Error(t, err)
}

func TestValidate_Required_RejectsWhitespaceAndZeroWidthOnly(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required"`
	}
	v := NewValidator()

	// Positive case: real content still passes.
	require.NoError(t, v.Validate(payload{Name: "Payments"}))

	for name, bad := range map[string]string{
		"pure whitespace":      "   \t\n  ",
		"zero-width space":     "\u200b\u200b",
		"zero-width + spaces":  "  \u200b \u200b  ",
		"non-breaking + ZWNBS": "\u00a0\ufeff",
	} {
		err := v.Validate(payload{Name: bad})
		require.Error(t, err, name)
	}
}

func TestValidate_Identifier(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"omitempty,identifier"`
	}
	v := NewValidator()

	for _, good := range []string{"", "Payments", "prod-db_01", "team 42"} {
		require.NoError(t, v.Validate(payload{Name: good}), good)
	}
	zwsp := string(rune(0x200B)) // ZERO WIDTH SPACE
	for _, bad := range []string{
		"=cmd|'/c calc'!A1",
		"name" + zwsp + "with" + zwsp + "zero" + zwsp + "width",
		"path/traversal",
		"<script>",
		"semicolon;here",
	} {
		require.Error(t, v.Validate(payload{Name: bad}), bad)
	}
}

func TestValidate_Omitempty_SkipsRemainingRules(t *testing.T) {
	type payload struct {
		Nickname string `json:"nickname" validate:"omitempty,min=3"`
	}
	v := NewValidator()

	// Empty → omitempty short-circuits, min is not enforced.
	require.NoError(t, v.Validate(payload{Nickname: ""}))
	// Present but too short → min applies.
	require.Error(t, v.Validate(payload{Nickname: "ab"}))
	// Present and long enough → ok.
	require.NoError(t, v.Validate(payload{Nickname: "abc"}))
}

func TestValidate_MinMax_StringLength(t *testing.T) {
	type payload struct {
		Code string `json:"code" validate:"min=2,max=4"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Code: "abc"}))
	require.Error(t, v.Validate(payload{Code: "a"}), "below min")
	require.Error(t, v.Validate(payload{Code: "abcde"}), "above max")
}

func TestValidate_MinMax_IntValue(t *testing.T) {
	type payload struct {
		Age int `json:"age" validate:"min=18,max=99"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Age: 30}))
	require.Error(t, v.Validate(payload{Age: 17}), "below min")
	require.Error(t, v.Validate(payload{Age: 100}), "above max")
}

func TestValidate_MinMax_UintValue(t *testing.T) {
	type payload struct {
		Count uint `json:"count" validate:"min=1,max=10"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Count: 5}))
	require.Error(t, v.Validate(payload{Count: 11}), "above max")
}

func TestValidate_Email(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"email"`
	}
	v := NewValidator()

	for _, good := range []string{"a@b.co", "user.name+tag@example.com"} {
		require.NoError(t, v.Validate(payload{Email: good}), good)
	}
	for _, bad := range []string{"no-at", "a@b", "a@.com", "@b.com"} {
		require.Error(t, v.Validate(payload{Email: bad}), bad)
	}
	// Empty is allowed by the rule itself (use `required` to forbid).
	require.NoError(t, v.Validate(payload{Email: ""}))
}

func TestValidate_URL(t *testing.T) {
	type payload struct {
		URL string `json:"url" validate:"url"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{URL: "https://example.com/x"}))
	require.NoError(t, v.Validate(payload{URL: "http://example.com"}))
	require.Error(t, v.Validate(payload{URL: "ftp://example.com"}))
	require.Error(t, v.Validate(payload{URL: "not a url"}))
}

func TestValidate_CharacterClasses(t *testing.T) {
	type payload struct {
		Alpha    string `json:"alpha" validate:"omitempty,alpha"`
		AlphaNum string `json:"alphanum" validate:"omitempty,alphanum"`
		Numeric  string `json:"numeric" validate:"omitempty,numeric"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Alpha: "abc", AlphaNum: "abc123", Numeric: "123"}))
	require.Error(t, v.Validate(payload{Alpha: "abc1"}), "alpha rejects digit")
	require.Error(t, v.Validate(payload{AlphaNum: "abc-1"}), "alphanum rejects dash")
	require.Error(t, v.Validate(payload{Numeric: "12a"}), "numeric rejects letter")
}

func TestValidate_OneOf(t *testing.T) {
	type payload struct {
		Env string `json:"env" validate:"oneof=dev staging prod"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Env: "staging"}))
	require.Error(t, v.Validate(payload{Env: "qa"}))
}

func TestValidate_UntaggedAndUnexportedFieldsSkipped(t *testing.T) {
	type payload struct {
		Tagged   string `json:"tagged" validate:"required"`
		Untagged string // no validate tag → ignored
		secret   string // unexported → ignored
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Tagged: "x"}))
	_ = payload{}.secret
}

func TestValidate_CollectsMultipleErrors(t *testing.T) {
	type payload struct {
		Name  string `json:"name" validate:"required"`
		Email string `json:"email" validate:"required,email"`
	}
	v := NewValidator()

	err := v.Validate(payload{Name: "", Email: "bad"})
	require.Error(t, err)
	ve, ok := err.(ValidationErrors)
	require.True(t, ok, "expected ValidationErrors")
	assert.GreaterOrEqual(t, len(ve.Errors), 2, "both fields should report errors")
}

func TestValidationErrors_ErrorString(t *testing.T) {
	ve := ValidationErrors{Errors: []ValidationError{
		{Field: "name", Message: "is required"},
		{Field: "age", Message: "must be at least 18"},
	}}
	got := ve.Error()
	assert.Contains(t, got, "name: is required")
	assert.Contains(t, got, "age: must be at least 18")
	assert.Contains(t, got, "; ")
}

func TestValidate_UsesJSONNameForErrorField(t *testing.T) {
	type payload struct {
		UserName string `json:"user_name" validate:"required"`
	}
	v := NewValidator()

	err := v.Validate(payload{})
	require.Error(t, err)
	ve := err.(ValidationErrors)
	require.Len(t, ve.Errors, 1)
	assert.Equal(t, "user_name", ve.Errors[0].Field, "json tag name preferred over Go field name")
}
