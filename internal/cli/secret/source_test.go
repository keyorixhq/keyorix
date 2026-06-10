package secret

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExplodeValue(t *testing.T) {
	defer func() { importNoExplode = false }()

	t.Run("flat JSON object explodes", func(t *testing.T) {
		importNoExplode = false
		got := explodeValue("db", `{"username":"u","password":"p"}`)
		names := names(got)
		assert.Equal(t, []string{"db-password", "db-username"}, names)
	})

	t.Run("plain string is a single secret", func(t *testing.T) {
		importNoExplode = false
		got := explodeValue("api-key", "sk_live_abc")
		assert.Len(t, got, 1)
		assert.Equal(t, "api-key", got[0].Name)
		assert.Equal(t, "sk_live_abc", got[0].Value)
	})

	t.Run("JSON array is not exploded", func(t *testing.T) {
		importNoExplode = false
		got := explodeValue("list", `["a","b"]`)
		assert.Len(t, got, 1)
		assert.Equal(t, `["a","b"]`, got[0].Value)
	})

	t.Run("nested object is stored whole", func(t *testing.T) {
		importNoExplode = false
		raw := `{"outer":{"inner":"v"}}`
		got := explodeValue("cfg", raw)
		assert.Len(t, got, 1)
		assert.Equal(t, raw, got[0].Value)
	})

	t.Run("numbers and bools become scalars", func(t *testing.T) {
		importNoExplode = false
		got := explodeValue("mix", `{"port":5432,"tls":true}`)
		m := map[string]string{}
		for _, e := range got {
			m[e.Name] = e.Value
		}
		assert.Equal(t, "5432", m["mix-port"])
		assert.Equal(t, "true", m["mix-tls"])
	})

	t.Run("no-explode keeps the object as one secret", func(t *testing.T) {
		importNoExplode = true
		raw := `{"username":"u","password":"p"}`
		got := explodeValue("db", raw)
		assert.Len(t, got, 1)
		assert.Equal(t, raw, got[0].Value)
	})
}

func TestSanitizeName(t *testing.T) {
	assert.Equal(t, "prod-db-password", sanitizeSecretName("prod/db/password"))
	assert.Equal(t, "a-b", sanitizeSecretName("a//b"))
	assert.Equal(t, "key", sanitizeSecretName("/key/"))
	assert.Equal(t, "with-space", sanitizeSecretName("with space"))
}

func names(entries []secretEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out
}
