package core

import (
	"context"
	"time"
)

func (m *MockStorage) UpsertMFAStepupToken(_ context.Context, _ uint, _ time.Time) error {
	return nil
}

func (m *MockStorage) HasActiveMFAStepup(_ context.Context, _ uint) (bool, error) {
	return false, nil
}
