package handlers

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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

// A legacy row (actor_type "") with an acting user reads as a human user; a
// machine row keeps its stored kind. (Was TestActorTypeOrDefault; the
// normalisation now lives in storage.AuditActorKind, #2951.)
func TestAuditActorKind_LegacyEmptyIsUserAndMachineKept(t *testing.T) {
	uid := uint(3)
	if got := storage.AuditActorKind(&models.AuditEvent{ActorType: "", UserID: &uid}); got != core.ActorTypeUser {
		t.Errorf("AuditActorKind(\"\", user) = %q, want %q", got, core.ActorTypeUser)
	}
	if got := storage.AuditActorKind(&models.AuditEvent{ActorType: core.ActorTypeMachine}); got != core.ActorTypeMachine {
		t.Errorf("AuditActorKind(machine) = %q, want %q", got, core.ActorTypeMachine)
	}
}

// storage cannot import core, so it spells the kinds itself: pin them.
func TestAuditActorKindConstantsMatchCore(t *testing.T) {
	sys := storage.AuditActorKind(&models.AuditEvent{ActorType: core.ActorTypeSystem, UserID: new(uint)})
	if sys != core.ActorTypeSystem {
		t.Errorf("system kind = %q, want %q", sys, core.ActorTypeSystem)
	}
	if got := storage.AuditActorKind(&models.AuditEvent{EventType: "x", ActorType: ""}); got != core.ActorTypeSystem {
		t.Errorf("no-principal kind = %q, want core.ActorTypeSystem %q", got, core.ActorTypeSystem)
	}
	uid := uint(1)
	if got := storage.AuditActorKind(&models.AuditEvent{ActorType: "", UserID: &uid}); got != core.ActorTypeUser {
		t.Errorf("user kind = %q, want core.ActorTypeUser %q", got, core.ActorTypeUser)
	}
}
