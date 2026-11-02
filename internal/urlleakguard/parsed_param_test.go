package urlleakguard

import (
	"go/parser"
	"go/token"
	"testing"
)

// TestURLLeakScannerParsedParameter is the red proof for the PARSED PARAMETER
// rule (#3805): notifychan's validateEndpoint named its URL `raw`, which the
// name rule does not match, and formatted it with %q.
func TestURLLeakScannerParsedParameter(t *testing.T) {
	const src = `package fixture

import (
	"context"
	"fmt"
	"log"
	"net/url"
)

func badRaw(raw string) error {
	if _, err := url.Parse(raw); err != nil {
		return err
	}
	return fmt.Errorf("endpoint %q must use https", raw)
}

func badSecondParam(ctx context.Context, n int, hook string) {
	if _, err := url.ParseRequestURI(hook); err != nil {
		return
	}
	log.Println("sending to " + hook)
}

func goodRedacted(raw string) error {
	_, _ = url.Parse(raw)
	return fmt.Errorf("endpoint %q", netutil.RedactURLHost(raw))
}

func goodNotParsed(raw string) {
	log.Printf("value %q", raw)
}

func goodOtherParam(raw, label string) error {
	_, _ = url.Parse(raw)
	return fmt.Errorf("bad %s", label)
}

func goodParsedOtherValue(label, raw string) error {
	_, _ = url.Parse(raw)
	return fmt.Errorf("bad %s", label)
}

func goodWrapped(raw string) error {
	_, err := url.Parse(raw)
	return fmt.Errorf("parse: %w", err)
}

func goodUnnamed(string) {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	hits := findLeaks(fset, file, "fixture.go")
	got := map[string]bool{}
	for _, h := range hits {
		got[h.name] = true
	}
	if len(hits) != 2 || !got["raw"] || !got["hook"] {
		t.Errorf("want exactly the raw and hook hits, got %d: %v", len(hits), hits)
	}
	for _, h := range hits {
		if h.line > 21 {
			t.Errorf("sanctioned or unrelated shape flagged: %s", h)
		}
	}
}
