package azurekms

import (
	"strings"
	"testing"
)

// kms_key_id and the vault origin are operator-configured URLs that can carry
// userinfo or a query; none of the construction errors may echo them.
func TestKeyIDErrors_CarryNoCredentials(t *testing.T) {
	const secret = "S3CRET-LEAK-MARKER"
	assertClean := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("want an error, got nil")
		}
		msg := err.Error()
		for _, leaked := range []string{secret, "admin", "sig=", "?"} {
			if strings.Contains(msg, leaked) {
				t.Errorf("error %q contains %q", msg, leaked)
			}
		}
	}

	t.Run("parseKeyID unparsable", func(t *testing.T) {
		_, _, _, err := parseKeyID("https://admin:" + secret + "/x@v.vault.azure.net/keys/k")
		assertClean(t, err)
	})
	t.Run("parseKeyID no scheme or host", func(t *testing.T) {
		_, _, _, err := parseKeyID("admin:" + secret + "@/keys/k?sig=" + secret)
		assertClean(t, err)
	})
	t.Run("validateKeyVaultHost unparsable", func(t *testing.T) {
		assertClean(t, validateKeyVaultHost("https://admin:"+secret+"/x@v.vault.azure.net"))
	})
	t.Run("validateKeyVaultHost not https", func(t *testing.T) {
		assertClean(t, validateKeyVaultHost("http://admin:"+secret+"@v.vault.azure.net/?sig="+secret))
	})
}
