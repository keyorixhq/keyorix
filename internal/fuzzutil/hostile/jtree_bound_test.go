package hostile

import (
	"bytes"
	"errors"
	"testing"
)

// ParseJSON refuses a document over MaxParseJSONBytes and still parses a normal one.
func TestParseJSONBounded(t *testing.T) {
	n, err := ParseJSON([]byte(`{"a":1,"a":[true,"x"]}`))
	if err != nil || n.K != KObj || len(n.Kids) != 2 {
		t.Fatalf("normal body: n=%+v err=%v", n, err)
	}
	big := append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), MaxParseJSONBytes)...)
	big = append(big, []byte(`"}`)...)
	if _, err := ParseJSON(big); !errors.Is(err, ErrJSONTooLarge) {
		t.Fatalf("oversized body: want ErrJSONTooLarge, got %v", err)
	}
}
