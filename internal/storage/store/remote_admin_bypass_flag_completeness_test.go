package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"RoleSetBypassesPermissionChecks": {statusIntentional,
			"ADR-084: roleSetContainsAdmin's 8 call sites (authz.go x5, dynamic_secrets.go, " +
				"invitations.go, scim_groups.go) either resolve roleIDs via scopedRoleIDs first " +
				"(Authorize, IsGlobalAdmin, requireAdminAuthorityAt, requireDynamicSecretAdminAuthority " +
				"all call scopedRoleIDs -> GetUserRoleIDsAt, an unconditional remoteUnsupported stub " +
				"per ADR-086, and return on that error before ever reaching roleSetContainsAdmin), or " +
				"take a pre-resolved roleIDs parameter whose own callers are dead: " +
				"requireMachinePrivilegeCeiling's only CLI trigger (machine token issue, " +
				"internal/cli/machine/token.go) is behind the NewRemoteClient raw-HTTP-passthrough " +
				"guard, and requireGlobalAdminToReinstateAdminRoles's callers (RestoreProject/" +
				"RestoreEnvironment/RestoreGroup) have no CLI command at all -- server/http-only, and " +
				"ADR-083 bars a server process from storage.type: remote regardless."},
		"SetRoleBypassesPermissionChecks": {statusIntentional,
			"ADR-084: written only by role seeding (defaultRoles/BootstrapSystem, " +
				"internal/core/auth_bootstrap.go). BootstrapSystem's only caller is " +
				"server/http/handlers/auth.go's /auth/bootstrap route -- server-only, and ADR-083 bars " +
				"a server process from storage.type: remote. No CreateRole/UpdateRole path (HTTP, " +
				"gRPC, any transport) accepts this value from a request DTO, by design -- see " +
				"models.Role.BypassesPermissionChecks's doc comment."},
	})
}
