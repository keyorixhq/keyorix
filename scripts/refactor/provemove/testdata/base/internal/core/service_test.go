package core

import "testing"

func helperT(t *testing.T) *Service {
	t.Helper()
	return NewService(defaultName)
}

func TestGreet(t *testing.T) {
	if got := helperT(t).Greet(); got != "hi x" {
		t.Fatal(got)
	}
}
