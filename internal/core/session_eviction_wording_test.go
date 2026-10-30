package core

import (
	"bytes"
	"errors"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// AUTHZ-ORACLE-TAILS-1 item 4: both listings failing is two failures with two
// wordings, one SECURITY log line each, and the per-user cache sweep runs once.
func TestSessionEviction_BothListingsFailing_AreNamedSeparately(t *testing.T) {
	c := NewKeyorixCore(nil)
	var swept []uint
	c.SetUserTokenCacheEvictor(func(id uint) { swept = append(swept, id) })
	logs := &bytes.Buffer{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	c.evictSessions(7, sessionEvictions{
		ListErr:    errors.New("injected: session listing unavailable"),
		PATListErr: errors.New("injected: PAT listing unavailable"),
	}, evictTombstone, "test")

	out := logs.String()
	assert.Contains(t, out, "could not list the sessions of user 7 (injected: session listing unavailable)")
	assert.Contains(t, out, "could not list the personal access tokens of user 7 (injected: PAT listing unavailable)")
	assert.Equal(t, []uint{7}, swept)
}
