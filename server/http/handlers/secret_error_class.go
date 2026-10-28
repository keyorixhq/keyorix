package handlers

import (
	"errors"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// Secret routes classify core's errors by KIND, never by message text: the
// leading part of every core message is a translated i18n string, so a text
// match answers 500 for a real 404/403 under de/es/fr/ru (#2461 class) and turns
// a storage failure whose wrapper happens to say "not found" into a 404.

// isSecretNotFound is a definitive "no such secret" (or "no such version of it").
func isSecretNotFound(err error) bool {
	return errors.Is(err, storage.ErrSecretNotFound) || errors.Is(err, storage.ErrSecretVersionNotFound)
}

// isPermissionRefusal is any core permission refusal (core.ErrPermissionDenied
// covers the specific sentinels too).
func isPermissionRefusal(err error) bool {
	return errors.Is(err, core.ErrPermissionDenied)
}
