package urlleakguard

// addr_rule_test.go — the ADDR rule of the REDACT-URLS-1 class guard (widened
// by CRYPTO-TAILS-3): a value named addr or address is a configured
// destination exactly when it is parsed as a URL, so it can carry the same
// token as an Endpoint or a DSN.
//
// # What the rule recognises
//
//   - NAMES: addr, address, or a camel-case/underscore suffix of either
//     (Addr, cfg.Address, vaultAddr, listen_address).
//   - ONLY WHEN PARSED: the name counts inside a function only if that
//     function passes the very same expression (x, or cfg.Addr) to url.Parse or
//     url.ParseRequestURI. A name that is never parsed as a URL is not flagged:
//     addr is far more often a host:port.
//   - HOST:PORT DIAL ADDRESSES ARE EXEMPT: an expression the function also
//     passes to net.SplitHostPort, net.JoinHostPort, net.Dial, net.DialTimeout,
//     net.ResolveTCPAddr, net.ResolveUDPAddr or net.Listen is a dial or listen
//     address, not a URL, and is never flagged (netutil.Dialer.DialContext,
//     netutil's TLS dial wrapper, evidencesink's pinned dial). The calls, the
//     verbs and the sanctioned wrapping are those of the main guard.
//
// # What it does not recognise
//
//   - A URL that is never passed to url.Parse in the same function (a field
//     read from config and formatted elsewhere) even when it is named addr.
//   - Anything the main guard does not see (methods on a logger value, other
//     modules, tests).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// addrName reports whether a name is addr/address or ends in one as a word.
func addrName(name string) bool { return hasNameSuffix(name, "addr", "address") }

// addrCallFirstArg returns the call's first argument when it is an identifier
// or selector, and the "pkg.Func" name of the call.
func addrCallFirstArg(n ast.Node) (arg ast.Expr, name string, ok bool) {
	call, isCall := n.(*ast.CallExpr)
	if !isCall || len(call.Args) == 0 {
		return nil, "", false
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return nil, "", false
	}
	pkg, isIdent := sel.X.(*ast.Ident)
	if !isIdent {
		return nil, "", false
	}
	return call.Args[0], pkg.Name + "." + sel.Sel.Name, true
}

var addrParseCalls = map[string]bool{"url.Parse": true, "url.ParseRequestURI": true}

// addrDialCalls are the calls whose argument is a host:port, not a URL.
var addrDialCalls = map[string]bool{
	"net.SplitHostPort": true, "net.JoinHostPort": true, "net.Dial": true,
	"net.DialTimeout": true, "net.ResolveTCPAddr": true, "net.ResolveUDPAddr": true,
	"net.Listen": true,
}

// urlAddrNames returns the addr-named expressions of fd that it parses as a
// URL and never treats as a host:port.
func urlAddrNames(fd *ast.FuncDecl) map[string]bool {
	if fd.Body == nil {
		return nil
	}
	parsed, dialed := map[string]bool{}, map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		arg, name, ok := addrCallFirstArg(n)
		if !ok {
			return true
		}
		if addrDialCalls[name] {
			// net.Dial(network, addr): the address is the second operand.
			for _, a := range n.(*ast.CallExpr).Args {
				if text, _ := sensitiveExprBy(a, func(_, last string) bool { return addrName(last) }); text != "" {
					dialed[text] = true
				}
			}
			return true
		}
		if !addrParseCalls[name] {
			return true
		}
		if text, ok := sensitiveExprBy(arg, func(_, last string) bool { return addrName(last) }); ok {
			parsed[text] = true
		}
		return true
	})
	for text := range dialed {
		delete(parsed, text)
	}
	return parsed
}

// findAddrLeaks scans one parsed file for the addr rule.
func findAddrLeaks(fset *token.FileSet, file *ast.File, path string) []leakHit {
	var hits []leakHit
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		names := urlAddrNames(fd)
		if len(names) == 0 {
			continue
		}
		hits = append(hits, scanDecl(fset, decl, path, func(e ast.Expr) (string, bool) {
			return sensitiveExprBy(e, func(text, _ string) bool { return names[text] })
		})...)
	}
	return hits
}

func TestNoConfiguredAddrURLFormattedIntoLogsOrErrors(t *testing.T) {
	g := guardrules.Rollout(t)
	for _, h := range scanRepo(t, findAddrLeaks) {
		g.Errorf("%s -- this addr/address value is parsed as a URL, so it can carry a token: name the "+
			"destination with netutil.RedactURLHost(...) and strip a wrapped *url.Error with "+
			"netutil.RedactErrorURLs(...)", h)
	}
}

// TestAddrRuleDialAddressesAreNotFlagged pins the three host:port dial
// addresses the rule must exempt, against the real files.
func TestAddrRuleDialAddressesAreNotFlagged(t *testing.T) {
	fset := token.NewFileSet()
	for _, rel := range []string{
		"internal/netutil/dialer.go",
		"internal/netutil/egress.go",
		"internal/evidencesink/objectstore.go",
	} {
		f, err := parser.ParseFile(fset, repoRoot()+"/"+rel, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if hits := findAddrLeaks(fset, f, rel); len(hits) != 0 {
			t.Errorf("%s: dial address flagged: %v", rel, hits)
		}
	}
}

// TestAddrRuleDetectsShapes is the red proof of the addr rule, both ways.
func TestAddrRuleDetectsShapes(t *testing.T) {
	const src = `package fixture

import (
	"fmt"
	"log"
	"net"
	"net/url"
)

func badParam(addr string) error {
	if _, err := url.Parse(addr); err != nil {
		return err
	}
	return fmt.Errorf("vault %q unreachable", addr)
}

func badField(cfg Config) {
	_, _ = url.ParseRequestURI(cfg.Address)
	log.Println("using " + cfg.Address)
}

func goodNotParsed(addr string) error {
	return fmt.Errorf("listen %q", addr)
}

func goodDial(addr string) error {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid dial address %q: %w", addr, err)
	}
	return nil
}

func goodDialedAndParsed(addr string) error {
	_, _ = url.Parse(addr)
	_, _ = net.Dial("tcp", addr)
	return fmt.Errorf("dial %q", addr)
}

func goodWrapped(addr string) error {
	_, _ = url.Parse(addr)
	return fmt.Errorf("vault %q", netutil.RedactURLHost(addr))
}

func goodOtherName(addr, label string) error {
	_, _ = url.Parse(addr)
	return fmt.Errorf("bad %s", label)
}

func goodNotAnAddrName(raw string) error {
	_, _ = url.Parse(raw)
	return fmt.Errorf("raw %q", raw)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	hits := findAddrLeaks(fset, file, "fixture.go")
	got := map[string]bool{}
	for _, h := range hits {
		got[h.name] = true
	}
	if len(hits) != 2 || !got["addr"] || !got["cfg.Address"] {
		t.Errorf("want exactly the addr and cfg.Address hits, got %d: %v", len(hits), hits)
	}
	for _, h := range hits {
		if h.line > 19 {
			t.Errorf("sanctioned or unrelated shape flagged: %s", h)
		}
	}
}

// TestAddrName pins the name matcher, including near-misses.
func TestAddrName(t *testing.T) {
	for _, n := range []string{"addr", "Addr", "address", "Address", "vaultAddr", "listen_address", "ADDR"} {
		if !addrName(n) {
			t.Errorf("%q should match", n)
		}
	}
	for _, n := range []string{"padr", "Paddr", "addrs", "Addresses", "ipaddr2", "raddr"} {
		if addrName(n) {
			t.Errorf("%q should not match", n)
		}
	}
}
