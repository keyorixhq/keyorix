package i18n

// i18n_inject_fuzz_test.go — ML1 injection-class fuzzing of localized message
// formatting (task ML1, piece 3: go-i18n message formats / x/text — format-verb
// injection and panic).
//
// Reachability note (recorded in the report): in PRODUCTION neither the
// messageID nor the TemplateData passed to Localize is attacker-controlled —
// every call site uses a hardcoded string-literal ID and nil data (confirmed by
// grep). x/text/message (printf-verb formatting) is NOT used anywhere; only
// x/text/language parsing is. So this target is a ROBUSTNESS / defense-in-depth
// target, not a live-attacker target: it proves the two properties that would
// matter if a future call site ever forwarded user data.
//
// Oracle:
//   1. No panic: Localize must never panic for any (messageID, data) — the
//      fallback path returns the messageID on any internal error.
//   2. Unknown-ID fallback invariant: an ID not present in any locale returns
//      the ID verbatim (the documented degradation).
//   3. No data-as-source injection (STRUCTURAL): a message template such as
//      "Hi {{.Name}}!" rendered with hostile data (containing {{...}}, %s, $(..))
//      must equal the output of an INDEPENDENT text/template execution of the
//      same template string with the same data — i.e. the data value is
//      substituted as a value and NEVER re-parsed as template source. If go-i18n
//      double-rendered, the two would diverge.
//
// What this oracle does NOT verify (report):
//   - It does not cover plural-form selection (PluralCount) or nested message
//     references — only a single {{.Name}} substitution shape.
//   - It trusts text/template as the reference oracle; it does not independently
//     re-derive text/template's own escaping/execution semantics.
//   - It cannot assert anything about a production injection because no
//     production call site forwards user data (see reachability note).

import (
	"strings"
	"sync"
	"testing"
	ttmpl "text/template"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

const (
	injGreetID   = "ml1_inject_greet"
	injGreetTmpl = "Hi {{.Name}}! You have access."
	injUnknownID = "ml1_inject_no_such_id_ever"
)

var injSetupOnce sync.Once

func injSetup(t *testing.T) {
	injSetupOnce.Do(func() {
		if err := InitializeForTesting(); err != nil {
			t.Fatalf("i18n init: %v", err)
		}
		// Register a template-bearing message under a non-shipped locale and
		// switch to it, so Localize renders injGreetTmpl via text/template.
		if _, err := RegisterPseudoLocaleForTesting("it", map[string]string{
			injGreetID: injGreetTmpl,
		}); err != nil {
			t.Fatalf("register pseudo locale: %v", err)
		}
	})
}

func FuzzI18nLocalizeFormat(f *testing.F) {
	for _, v := range []string{
		"Alice",
		"{{.Secret}}",              // template action in data — must NOT evaluate
		"{{printf \"%s\" .Name}}",  // function call in data
		"%s %d %v",                 // printf verbs — go-i18n is not printf-based
		"$(whoami)",                // shell-looking
		"{{/* comment */}}",        //
		"{{.}}",                    //
		"<b>html</b>",              // text/template does not escape
		"line\nbreak",              //
		strings.Repeat("x", 10000), //
		"",                         //
		"\x00",                     //
	} {
		f.Add(v)
	}

	f.Fuzz(func(t *testing.T, value string) {
		injSetup(t)
		l := GetLocalizer()
		data := map[string]any{"Name": value}

		// Oracle 1 + 3: known template message, compared to an independent
		// text/template execution.
		var got string
		fuzzutil.Guard(t.Fatalf, "i18n.Localize", func() {
			got = l.Localize(injGreetID, data)
		})

		want, refErr := refRender(injGreetTmpl, data)
		if refErr != nil {
			// The reference template itself failed to execute for this data —
			// then Localize is allowed to fall back to the message ID. Accept
			// either the reference failure-equivalent or the ID fallback.
			if got != injGreetID {
				t.Fatalf("Localize(%q) with data %q = %q; reference render errored (%v) so expected ID fallback", injGreetID, value, got, refErr)
			}
			return
		}
		if got != want {
			t.Fatalf("i18n data-as-source divergence:\nLocalize = %q\nreference text/template = %q\n(value=%q)", got, want, value)
		}

		// Oracle 2: unknown ID returns the ID verbatim, never panics.
		var unk string
		fuzzutil.Guard(t.Fatalf, "i18n.Localize.unknown", func() {
			unk = l.Localize(injUnknownID, data)
		})
		if unk != injUnknownID {
			t.Fatalf("unknown-ID fallback broken: got %q want %q", unk, injUnknownID)
		}
	})
}

// refRender executes tmpl with text/template — the independent oracle for what a
// correct, single-pass substitution must produce.
func refRender(tmpl string, data map[string]any) (string, error) {
	tp, err := ttmpl.New("ref").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := tp.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}
