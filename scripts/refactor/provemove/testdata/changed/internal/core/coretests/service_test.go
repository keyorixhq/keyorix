package coretests

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

func helperT(t *testing.T) *core.Service {
	t.Helper()
	return core.NewService(core.DefaultTitle)
}

func TestGreet(t *testing.T) {
	if got := helperT(t).Greet(); got != "hi x" {
		t.Fatal(got)
	}
}
