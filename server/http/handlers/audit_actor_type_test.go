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
