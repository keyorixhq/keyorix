// Planted red fixture for TestMachineActorArgumentGuard_Calibration: every method
// below passes something other than the request's machine actor. Parsed only, never
// compiled.
package fixture

func (h *FixtureHandler) addMemberConstant(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddProjectMember(r.Context(), userCtx.UserID, 1, 2, "viewer", false)
}

func (h *FixtureHandler) addMemberWrongField(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddProjectMember(r.Context(), userCtx.UserID, 1, 2, "viewer", userCtx.IsAdmin)
}

func (h *FixtureHandler) setRoleHumanKind(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.SetProjectMemberRole(r.Context(), userCtx.UserID, 1, 2, "viewer", userCtx.ActorKind() == core.ActorTypeUser)
}

func (h *FixtureHandler) assignOverwritten(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	isMachine := userCtx.ActorKind() == core.ActorTypeMachine
	isMachine = false
	_ = h.coreService.AssignUserRole(r.Context(), userCtx.UserID, 2, 3, core.Scope{}, isMachine)
}

func (h *FixtureHandler) groupMemberLocalFalse(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	isMachine := false
	_ = h.coreService.AddUserToGroup(r.Context(), userCtx.UserID, isMachine, 2, 3, 0)
}

func (h *FixtureHandler) rejectZeroMachine(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_, _ = h.coreService.RejectSecretAccessRequest(r.Context(), 7, userCtx.UserID, 0, "no")
}

// A storage method sharing a family name but not its arity is not a call site.
func (h *FixtureHandler) storageSameName(w http.ResponseWriter, r *http.Request) {
	_ = h.storage.AddProjectMember(r.Context(), 1, 2)
}
