// error_class_locale_helper_test.go — shared locale switch for the
// "status is a function of the failure, not of the language" table tests
// (ERRLOSS-SENTINELS-1). Same technique as withTranslatedErrorMessages
// (break_glass_activate_revoke_locale_test.go, #2905): a pseudo-locale that
// translates every i18n key a not-found or refusal text is built from, so a
// handler that still classifies by message text falls through to 500 here
// exactly as it does under de/es/fr/ru in production.
package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// errorClassLocales is the locale axis of every family table: the shipped
// English text and a translated one.
var errorClassLocales = []string{"en", pseudoLocale}

// withErrorTextLocale activates lang for the test. "en" is the stock localizer;
// pseudoLocale translates every not-found / refusal / validation prefix.
// Tests using it flip the process-global localizer and must NOT be t.Parallel().
func withErrorTextLocale(t *testing.T, lang string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	if lang == "en" {
		return
	}
	restore, err := i18n.RegisterPseudoLocaleForTesting(lang, map[string]string{
		"ErrorUserNotFound":      "пользователь отсутствует",
		"ErrorUnauthorized":      "нет доступа",
		"ErrorPermissionDenied":  "доступ запрещён",
		"ErrorNotFound":          "ресурс отсутствует",
		"ErrorSecretNotFound":    "секрет отсутствует",
		"ErrorVersionNotFound":   "версия отсутствует",
		"ErrorRoleNotFound":      "роль отсутствует",
		"ErrorShareNotFound":     "доступ не найден в списке",
		"ErrorValidation":        "ошибка проверки",
		"ErrorRetrievalFailed":   "сбой получения данных",
		"ErrorStorageFailed":     "сбой хранилища",
		"ErrorDatabaseOperation": "сбой базы данных",
	})
	require.NoError(t, err)
	t.Cleanup(restore)
	// Floor: if the override ever stopped applying, the translated half would
	// silently run in English and prove nothing.
	require.Equal(t, "пользователь отсутствует", i18n.T("ErrorUserNotFound", nil))
	require.NotContains(t, i18n.T("ErrorNotFound", nil), "not found")
}
