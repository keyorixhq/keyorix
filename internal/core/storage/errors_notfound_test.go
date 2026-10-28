package storage_test

import (
	"errors"
	"fmt"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestNotFound_KeepsTextAndMatchesSentinelAndCause(t *testing.T) {
	err := storage.NotFound(storage.ErrShareNotFound, "Свёрнутый текст", gorm.ErrRecordNotFound)
	if err.Error() != "Свёрнутый текст" {
		t.Fatalf("text changed: %q", err.Error())
	}
	wrapped := fmt.Errorf("outer: %w", err)
	if !errors.Is(wrapped, storage.ErrShareNotFound) {
		t.Error("must match sentinel through an extra wrap")
	}
	if !errors.Is(wrapped, gorm.ErrRecordNotFound) {
		t.Error("must still match the gorm cause")
	}
	if errors.Is(wrapped, storage.ErrSecretTemplateNotFound) {
		t.Error("must not match a different entity's sentinel")
	}
	if got := storage.NotFound(storage.ErrShareNotFound, "x", nil); !errors.Is(got, storage.ErrShareNotFound) {
		t.Error("nil cause must still match the sentinel")
	}
}

func TestNotFoundSentinels_DistinctAndNotMatchedByDriverError(t *testing.T) {
	sentinels := []error{
		storage.ErrNotificationChannelNotFound, storage.ErrMachineCredentialNotFound,
		storage.ErrOIDCBindingNotFound, storage.ErrConnectorBindingNotFound,
		storage.ErrSecretTemplateNotFound, storage.ErrShareNotFound,
		storage.ErrSSOLoginStateNotFound, storage.ErrPermissionNotFound,
		storage.ErrAlertEscalationNotFound, storage.ErrRotationPolicyNotFound,
	}
	driverErr := fmt.Errorf("retrieval failed: %w", errors.New("database is closed"))
	for i, a := range sentinels {
		if errors.Is(driverErr, a) {
			t.Errorf("driver error matches %v", a)
		}
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v matches %v", a, b)
			}
		}
	}
}
