package store

import (
	"strings"
	"testing"
)

// TestQueryBuilder_EscapesInjection pins that user-controlled filter values can't
// inject extra query params or truncate the query.
func TestQueryBuilder_EscapesInjection(t *testing.T) {
	q := newQueryBuilder()
	q.add("type", "1&owner_id=999")
	q.add("search", "a#b")
	out := q.String()
	if strings.Contains(out, "owner_id=999") {
		t.Fatalf("'&' injection not escaped: %s", out)
	}
	if strings.Contains(out, "#") {
		t.Fatalf("'#' not escaped: %s", out)
	}
	if !strings.Contains(out, "1%26owner_id%3D999") {
		t.Fatalf("value not percent-encoded: %s", out)
	}
}
