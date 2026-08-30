package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListConnectorProjectBindings": {statusIntentional,
			"#1477/#1479: backs only the boot-time drift warning (server/main.go warnConnectConfigDrift), which runs against the resolving server's own storage right after SetConnectOwnership — a server on storage.type: remote never reaches this code path (ADR-083), same reasoning as the RBAC primitives in remote_rbac.go"},
		"GetConnectorProjectBinding": {statusIntentional,
			"#1480: zero internal/core caller confirmed -- its only real caller, repo-wide, was server/main.go's resolveConnectorOwnership at boot time, which calls storage.Storage methods directly against coreService.Storage() (never RemoteStorage, since ADR-083's validateRemoteStorageNotServer rejects storage.type: remote for any server process). Its only real HTTP caller was its own /system proxy handler, GetConnectorProjectBindingProxy (server/http/handlers/connector_project_bindings_proxy.go), now removed."},
		"CreateConnectorProjectBinding": {statusIntentional,
			"#1480: zero internal/core caller confirmed -- its only real caller, repo-wide, was its own /system proxy handler, CreateConnectorProjectBindingProxy (server/http/handlers/connector_project_bindings_proxy.go), now removed. That handler backed a \"downstream Keyorix server proxying to an upstream\" topology ADR-083 (validateRemoteStorageNotServer) forecloses entirely."},
	})
}
