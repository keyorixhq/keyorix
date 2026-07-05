package rotation

import (
	"context"
	"strings"
	"testing"
)

// FuzzAzureGenerateUpstreamRef fuzzes the ref interpolated into the Microsoft
// Graph URL path by AzureAppSecretExecutor.GenerateUpstream (azure.go), the
// executor whose own doc comment documents the exact bug this campaign already
// found and fixed here: "ref is interpolated into the Graph URL path... a
// crafted ref that begins with an allowed prefix (e.g.
// '<allowed-guid>/../<victim-guid>') could path-traverse to a different
// application and defeat allowed_refs." GenerateUpstream now rejects any
// path/query metacharacter up front (strings.ContainsAny(ref, "/?#%")) before
// the ref ever reaches url.PathEscape / the Graph client.
//
// This fuzzes the same invariant the existing regression test
// (TestAzure_GenerateUpstream_Errors/"ref with path metacharacters rejected")
// checks for one fixed malicious ref, but over the whole input space: (a)
// GenerateUpstream must never panic, and (b) it must never let a ref containing
// one of those metacharacters reach the Graph client (fake.addedFor) — i.e.
// every ref that reaches the upstream call must be metacharacter-free.
func FuzzAzureGenerateUpstreamRef(f *testing.F) {
	// Seed corpus: a legitimate GUID-shaped ref, the exact path-traversal string
	// the existing regression test uses, and a handful of other metacharacter
	// shapes an attacker might try against the prefix allowlist.
	f.Add("app-123")
	f.Add("app-1/../victim-2")
	f.Add("app-1/../../etc/passwd")
	f.Add("app-1?x=1")
	f.Add("app-1#frag")
	f.Add("app-1%2e%2e%2fvictim")
	f.Add("")
	f.Add("app-")
	f.Add(strings.Repeat("app-1/", 50) + "victim")

	f.Fuzz(func(t *testing.T, ref string) {
		fake := &fakeAzure{newSecret: "n3w-secret"}
		e := azureWith(fake, "app-") // prefix allowlist an attacker might try to defeat

		_, err := e.GenerateUpstream(context.Background(), ref)

		if strings.ContainsAny(ref, "/?#%") {
			if err == nil {
				t.Fatalf("GenerateUpstream accepted a ref containing a path/query metacharacter: %q", ref)
			}
			if fake.addedFor != "" {
				t.Fatalf("a metacharacter-bearing ref reached the Graph client: ref=%q addedFor=%q", ref, fake.addedFor)
			}
			return
		}
		// No metacharacters: it may still be rejected by the allowed_refs prefix
		// check or the empty-ref check, but if it DID reach the upstream client,
		// the exact ref (unmodified) must be what was sent — never a mangled or
		// differently-scoped value.
		if fake.addedFor != "" && fake.addedFor != ref {
			t.Fatalf("Graph client received a different ref than was requested: requested=%q sent=%q", ref, fake.addedFor)
		}
	})
}
