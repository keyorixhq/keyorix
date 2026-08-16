package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"WithBootstrapLock": {statusIntentional,
			"#core-auth-03: BootstrapSystem always runs against LocalStorage inside the server process (its only caller is the HTTP POST /system/init handler) — nothing calls it against RemoteStorage, and a remote caller would get no real cross-process guarantee anyway (no shared advisory lock to take over HTTP), same reasoning as WithAuditCheckpointLock"},
	})
}
