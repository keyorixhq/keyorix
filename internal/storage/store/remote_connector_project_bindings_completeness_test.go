package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListConnectorProjectBindings": {statusIntentional,
			"#1477/#1479: backs only the boot-time drift warning (server/main.go warnConnectConfigDrift), which runs against the resolving server's own storage right after SetConnectOwnership — a server on storage.type: remote never reaches this code path (ADR-083), same reasoning as the RBAC primitives in remote_rbac.go"},
	})
}
