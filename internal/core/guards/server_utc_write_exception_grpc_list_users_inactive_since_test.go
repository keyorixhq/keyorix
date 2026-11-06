package guards

func init() {
	registerServerTimeWriteException("grpc:user_service.go:ListUsers:InactiveSince",
		"host-clock cutoff for a read filter; storage.ListUsers applies filter.InactiveSince.UTC() before comparing with last_login_at and "+
			"created_at (local_users.go), and the HTTP twin users_list.go already passes UTC")
}
