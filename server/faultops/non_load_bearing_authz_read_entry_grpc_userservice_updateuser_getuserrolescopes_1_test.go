// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	registerNonLoadBearingAuthzRead("grpc_userservice_updateuser_getuserrolescopes_1", nonLoadBearingException{
		op: "GRPC keyorix.v1.UserService.UpdateUser", method: "GetUserRoleScopes", nth: 1,
		designComment: "internal/core/authz.go requireEqualOrGreaterAdminAuthority reads the target's roles with " +
			"GetUserScopedRoleSets (one statement, #4025) and returns errCeilingResolutionFailed on error, so the " +
			"update is refused; server/grpc/services/user_service.go UpdateUser then reaches GetUserRoleScopes only via " +
			"userToProto -> projectCounts (besteffort.Run), after the update committed",
		provingTest: "server/grpc/services/TestUpdateUser_RoleScopesFaultFailsClosedOnCeilingOnly",
		why: "This call is response enrichment for the updated target user, after authorization (users.write via " +
			"AuthorizePrincipal, and the ceiling's GetUserScopedRoleSets) has already failed closed or passed. A fault " +
			"there leaves the committed update in place with zero project counts, projectCounts' documented best-effort " +
			"fallback; the authorization-bearing ceiling read is not exempted.",
	})
}
