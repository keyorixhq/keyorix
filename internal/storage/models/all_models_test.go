package models

import "testing"

func TestAllTestModels_NonEmpty(t *testing.T) {
	if len(AllTestModels()) == 0 {
		t.Fatal("AllTestModels must not be empty")
	}
}
