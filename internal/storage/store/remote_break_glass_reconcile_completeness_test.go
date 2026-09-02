package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ReconcileExpiredBreakGlassActivation": {statusIntentional,
			"#1653 reopened: server-internal primitive called only from internal/core.ActivateBreakGlass, " +
				"immediately before CreateBreakGlassActivation -- itself remoteUnsupported (no live caller in " +
				"either topology, G80 liveness sweep). Unreachable under storage.type: remote for the identical " +
				"reason CreateBreakGlassActivation is."},
	})
}
