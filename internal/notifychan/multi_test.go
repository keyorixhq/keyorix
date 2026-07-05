package notifychan

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
)

type countingSink struct {
	n      int
	refuse bool // simulates a sink that has nowhere to route the event (#221)
}

func (c *countingSink) Deliver(core.NotificationEvent) bool {
	if c.refuse {
		return false
	}
	c.n++
	return true
}

func TestNewMulti_FansOutToAll(t *testing.T) {
	a, b := &countingSink{}, &countingSink{}
	sink := NewMulti(a, b)
	attempted := sink.Deliver(core.NotificationEvent{UserID: 1})
	assert.Equal(t, 1, a.n)
	assert.Equal(t, 1, b.n)
	assert.True(t, attempted)
}

// TestNewMulti_AttemptedTrueIfAnySinkAccepts is a regression test for #221: a
// broadcast must not be reported as failed just because ONE of several channels
// couldn't take it — only when NONE of them could.
func TestNewMulti_AttemptedTrueIfAnySinkAccepts(t *testing.T) {
	accepts, refuses := &countingSink{}, &countingSink{refuse: true}
	sink := NewMulti(refuses, accepts)
	attempted := sink.Deliver(core.NotificationEvent{UserID: 1})
	assert.True(t, attempted, "at least one sink accepted the event")
	assert.Equal(t, 1, accepts.n)
	assert.Equal(t, 0, refuses.n)
}

// TestNewMulti_AttemptedFalseIfEverySinkRefuses is a regression test for #221: when
// every wrapped sink is a no-op for this event, the fan-out must say so rather than
// silently claim success.
func TestNewMulti_AttemptedFalseIfEverySinkRefuses(t *testing.T) {
	a, b := &countingSink{refuse: true}, &countingSink{refuse: true}
	sink := NewMulti(a, b)
	attempted := sink.Deliver(core.NotificationEvent{UserID: 1})
	assert.False(t, attempted, "no sink accepted the event — must not claim success")
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
