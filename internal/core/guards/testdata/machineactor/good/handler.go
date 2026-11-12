// Planted green fixture for TestMachineActorArgumentGuard_Calibration: one call per
// recognised form of the request's machine actor. Parsed only, never compiled.
package fixture

func (h *FixtureHandler) addMemberActorKind(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddProjectMember(r.Context(), userCtx.UserID, 1, 2, "viewer", userCtx.ActorKind() == core.ActorTypeMachine)
}

func (h *FixtureHandler) setRoleReversedOperands(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.SetProjectMemberRole(r.Context(), userCtx.UserID, 1, 2, "viewer", (core.ActorTypeMachine == userCtx.ActorKind()))
}

func (h *FixtureHandler) groupMemberHelper(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	_ = h.coreService.AddUserToGroup(r.Context(), userCtx.UserID, isMachineActor(r), 2, 3, 0)
}

func (h *FixtureHandler) assignLocalCopy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	kind := userCtx.ActorKind() == core.ActorTypeMachine
	isMachine := kind
	_ = h.coreService.AssignUserRole(r.Context(), userCtx.UserID, 2, 3, core.Scope{}, isMachine)
}

func (h *FixtureHandler) createUserGrantCtx(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	ctx, isMachine := creationGrantCtx(r, userCtx)
	_, _ = h.coreService.CreateUserAudited(ctx, nil, userCtx.UserID, isMachine)
}

func (h *FixtureHandler) rejectDerefMachineID(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	var approverMachineID uint
	if actor.MachineIdentityID != nil {
		approverMachineID = *actor.MachineIdentityID
	}
	_, _ = h.coreService.RejectSecretAccessRequest(r.Context(), 7, actor.UserID, approverMachineID, "no")
}

func (h *FixtureHandler) approveHelperMachineID(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	_, _ = h.coreService.ApproveAccessRequestWithExpiry(r.Context(), 1, 2, actor.UserID, machineID(r), "viewer", 0)
}
