package store

func init() {
	// Notification channel management — the REST API (/api/v1/notification-channels)
	// is the remote surface. The CLI uses common.RemoteClient directly against those
	// endpoints; the storage layer is only ever reached from the server-side handler
	// which always runs against LocalStorage.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListNotificationChannels":      {statusIntentional, "notification channel CRUD is managed via /api/v1/notification-channels; raw storage call never reached from a remote-storage caller"},
		"GetNotificationChannel":        {statusIntentional, "notification channel CRUD is managed via /api/v1/notification-channels; raw storage call never reached from a remote-storage caller"},
		"GetNotificationChannelByName":  {statusIntentional, "notification channel CRUD is managed via /api/v1/notification-channels; raw storage call never reached from a remote-storage caller"},
		"CreateNotificationChannel":     {statusIntentional, "notification channel CRUD is managed via /api/v1/notification-channels; raw storage call never reached from a remote-storage caller"},
		"UpdateNotificationChannel":     {statusIntentional, "notification channel CRUD is managed via /api/v1/notification-channels; raw storage call never reached from a remote-storage caller"},
		"DeleteNotificationChannel":     {statusIntentional, "notification channel CRUD is managed via /api/v1/notification-channels; raw storage call never reached from a remote-storage caller"},
		"UpdateNotificationRetryPolicy": {statusIntentional, "retry policy update is managed via /api/v1/notification-channels/{id}/retry-policy; raw storage call never reached from a remote-storage caller"},
	})
}
