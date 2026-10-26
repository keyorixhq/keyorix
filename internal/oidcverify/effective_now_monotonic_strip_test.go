package oidcverify

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// hasMonotonicReading is a copy of internal/core's helper
// (clock_watermark_monotonic_strip_test.go).
func hasMonotonicReading(t time.Time) bool {
	return strings.Contains(t.String(), " m=")
}

// TestOIDCEffectiveNow_StripMonotonicReading is the OIDCVerifier.effectiveNow
// case of internal/core's TestConnectShareOIDCEffectiveNow_StripMonotonicReading,
// moved here with the verifier (CORE-PURE-AUTH-LEAVES-1): same body.
func TestOIDCEffectiveNow_StripMonotonicReading(t *testing.T) {
	t.Parallel()
	t.Run("OIDCVerifier.effectiveNow", func(t *testing.T) {
		v := &OIDCVerifier{now: time.Now}
		got := v.effectiveNow()
		assert.False(t, hasMonotonicReading(got))
	})
}
