package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"WithNamedLock": {statusIntentional,
			"#1646: every WithNamedLock caller (role/group grant assignment, project-admin and last-admin lockout guards) runs only inside the server process against LocalStorage -- a remote caller would get no real cross-process guarantee anyway (no shared advisory lock to take over HTTP), same reasoning as WithBootstrapLock"},
	})
}
