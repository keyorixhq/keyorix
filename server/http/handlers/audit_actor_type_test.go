package handlers

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestValidActorType(t *testing.T) {
	valid := []string{core.ActorTypeUser, core.ActorTypeMachine, core.ActorTypeSystem}
	for _, v := range valid {
		if !validActorType(v) {
			t.Errorf("validActorType(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "User", "robot", "machine"} {
		if validActorType(v) {
			t.Errorf("validActorType(%q) = true, want false", v)
		}
	}
}

func TestActorTypeOrDefault(t *testing.T) {
	if got := actorTypeOrDefault(""); got != core.ActorTypeUser {
		t.Errorf("actorTypeOrDefault(\"\") = %q, want %q", got, core.ActorTypeUser)
	}
	if got := actorTypeOrDefault(core.ActorTypeMachine); got != core.ActorTypeMachine {
		t.Errorf("actorTypeOrDefault(machine) = %q, want %q", got, core.ActorTypeMachine)
	}
}

// #2951 item 1: an event with no acting user is shown with actor "system"
// (core.ResolveUsernames maps user id 0), so its KIND must read "system" too,
// whether the row stores actor_type "" (legacy) or the column default "user".
func TestDisplayActorType_SystemWhenNoActingUser(t *testing.T) {
	uid := uint(7)
	zero := uint(0)
	cases := []struct {
		name   string
		stored string
		userID *uint
		want   string
	}{
		{"legacy empty, no user", "", nil, core.ActorTypeSystem},
		{"default user, no user", core.ActorTypeUser, nil, core.ActorTypeSystem},
		{"default user, user id 0", core.ActorTypeUser, &zero, core.ActorTypeSystem},
		{"explicit system", core.ActorTypeSystem, nil, core.ActorTypeSystem},
		{"explicit system with user", core.ActorTypeSystem, &uid, core.ActorTypeSystem},
		{"legacy empty, real user", "", &uid, core.ActorTypeUser},
		{"user, real user", core.ActorTypeUser, &uid, core.ActorTypeUser},
		{"machine, no user", core.ActorTypeMachine, nil, core.ActorTypeMachine},
		{"machine, with user", core.ActorTypeMachine, &uid, core.ActorTypeMachine},
	}
	for _, c := range cases {
		if got := displayActorType(c.stored, c.userID); got != c.want {
			t.Errorf("%s: displayActorType(%q, %v) = %q, want %q", c.name, c.stored, c.userID, got, c.want)
		}
	}
}
