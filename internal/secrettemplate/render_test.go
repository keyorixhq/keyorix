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
