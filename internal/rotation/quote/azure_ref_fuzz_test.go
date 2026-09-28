package quote

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzAzureRefValidation fuzzes ValidateAzureRef, the pure security check extracted from
// AzureAppSecretExecutor.GenerateUpstream (internal/rotation/azure.go). It is a NEW,
// additional pure fuzz target — not a 1:1 move of internal/rotation's own
// FuzzAzureGenerateUpstreamRef, which STAYS in package rotation because it also exercises
// GenerateUpstream's real Microsoft Graph client interaction via a fake, an I/O-shaped
// test that cannot become leaf-package-pure without dropping that coverage. See azure.go's
// doc comment on the finding this guards: "ref is interpolated into the Graph URL
// path... a crafted ref that begins with an allowed prefix (e.g.
// '<allowed-guid>/../<victim-guid>') could path-traverse to a different application and
// defeat allowed_refs."
//
// Invariants: (a) never panics/hangs; (b) any ref containing a path/query metacharacter
// ("/?#%") is always rejected with a non-nil error, regardless of allowedRefs content —
// the same property FuzzAzureGenerateUpstreamRef checks at the GenerateUpstream level,
// checked here at the pure-validation level instead.
func FuzzAzureRefValidation(f *testing.F) {
	f.Add("app-123", "app-")
	f.Add("app-1/../victim-2", "app-")
	f.Add("app-1/../../etc/passwd", "app-")
	f.Add("app-1?x=1", "app-")
	f.Add("app-1#frag", "app-")
	f.Add("app-1%2e%2e%2fvictim", "app-")
	f.Add("", "app-")
	f.Add("app-", "app-")
	f.Add(strings.Repeat("app-1/", 50)+"victim", "app-")
	f.Add("app-123", "")

	f.Fuzz(func(t *testing.T, ref, allowedRefsCSV string) {
		var allowedRefs []string
		if allowedRefsCSV != "" {
			allowedRefs = strings.Split(allowedRefsCSV, ",")
		}

		var err error
		fuzzutil.Guard(t.Fatalf, "ValidateAzureRef", func() { err = ValidateAzureRef("test-backend", ref, allowedRefs) })

		if strings.ContainsAny(ref, "/?#%") && err == nil {
			t.Fatalf("ValidateAzureRef accepted a ref containing a path/query metacharacter: %q", ref)
		}
	})
}
