package guards

// share_list_cap_guard_test.go — REVIEW-3018, the family guard for the share-list
// truncation refusal (INV-CORE-share-list-refused-at-fetch-cap).
// storage.ListSharesByUser / ListSharesByOwner return at most maxUnboundedListRows
// rows and cut the rest off silently; a caller that hands such a list on unchecked
// shows a shortened list as if it were complete. ListSharesByUser (gRPC/CLI) was the
// instance that slipped: the HTTP view and the owner-scoped list refused at the cap,
// the gRPC/CLI merge did not. The shared-with-me secret listing and the dashboard's
// share counts were the two siblings this guard found.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// shareListFetches are the calls whose result may be silently truncated.
// sharesReceivedAndOwned is the shared two-fetch helper: it is a fetch itself,
// so each of ITS callers is held to the rule.
var shareListFetches = map[string]bool{
	"ListSharesByUser":       true, // c.storage.ListSharesByUser
	"ListSharesByOwner":      true, // c.storage.ListSharesByOwner
	"sharesReceivedAndOwned": true,
}

// shareListCapExempt: "file.go:Func" callers that read a share fetch without the
// refusal, each with why. The guard fails on an entry that no longer calls a fetch.
var shareListCapExempt = map[string]string{
	"sharing_query.go:sharesReceivedAndOwned": "the fetch helper itself; its callers are checked",
	"permissions.go:ListUserPermissions": "no production caller (see its own comment); a truncated list there " +
		"only omits share grants, which fails closed",
}

// TestShareListFetchCallersRefuseAtTheCap: every core family function that calls a
// share-list fetch must also call shareFetchMayBeTruncated, or be listed in
// shareListCapExempt with its reason.
//
// Population, and what it does not see: every non-test .go file of the core family
// (coreFamilySources), every FuncDecl whose body contains a call whose selector or
// identifier name is in shareListFetches. A fetch reached through a func value or
// another wrapper not named above would not be caught; add such a wrapper to
// shareListFetches with the same rule. It checks that the refusal is called, not
// that its result is acted on.
func TestShareListFetchCallersRefuseAtTheCap(t *testing.T) {
	g := guardrules.Rollout(t)
	callers := map[string]bool{}
	var missing []string
	for _, path := range coreFamilySources(t) {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel := srcpath.CoreFamilyRel(path)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fetches, refuses := false, false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fun := ce.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				fetches = fetches || shareListFetches[callee]
				refuses = refuses || callee == "shareFetchMayBeTruncated"
				return true
			})
			if !fetches {
				continue
			}
			key := rel + ":" + fd.Name.Name
			callers[key] = true
			if _, ok := shareListCapExempt[key]; !ok && !refuses {
				missing = append(missing, key)
			}
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		g.Errorf("%s reads a share-list fetch that storage may have truncated at its row cap, but never "+
			"calls shareFetchMayBeTruncated: refuse with ErrShareListOverCap (or degrade a count), never "+
			"return a silently shortened list (REVIEW-3018)", key)
	}

	// Non-vacuous: the refusing callers this guard was written for are in the population.
	for _, want := range []string{
		"sharing_query.go:ListSharesByUser", "sharing_query.go:ListUserShareViews",
		"share_owned_list.go:ListOwnedShareViews", "secret_listing_query.go:getSharedSecretsWithSharingInfo",
		"dashboard.go:GetDashboardStats",
	} {
		if !callers[want] {
			g.Errorf("%s is no longer seen as a share-list fetch caller; the guard's population drifted", want)
		}
	}
	var stale []string
	for key := range shareListCapExempt {
		if !callers[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		g.Errorf("shareListCapExempt entry %q no longer calls a share-list fetch; remove it", key)
	}
}
