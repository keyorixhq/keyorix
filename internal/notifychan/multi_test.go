package notifychan

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
)

type countingSink struct{ n int }

func (c *countingSink) Deliver(core.NotificationEvent) { c.n++ }

func TestNewMulti_FansOutToAll(t *testing.T) {
	a, b := &countingSink{}, &countingSink{}
	sink := NewMulti(a, b)
	sink.Deliver(core.NotificationEvent{UserID: 1})
	assert.Equal(t, 1, a.n)
	assert.Equal(t, 1, b.n)
}

func TestNewMulti_NilWhenNoLiveSinks(t *testing.T) {
	assert.Nil(t, NewMulti())
	assert.Nil(t, NewMulti(nil, nil))
}

func TestNewMulti_UnwrapsSingle(t *testing.T) {
	a := &countingSink{}
	sink := NewMulti(nil, a)
	// A lone live sink is returned directly (not wrapped).
	assert.Equal(t, core.NotificationSink(a), sink)
	sink.Deliver(core.NotificationEvent{UserID: 1})
	assert.Equal(t, 1, a.n)
}
