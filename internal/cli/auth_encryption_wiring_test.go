package cli

// auth_encryption_wiring_test.go — regression test for #292: AuthEncryptionCmd
// was defined but never reached rootCmd, so `keyorix encryption auth-encryption`
// failed with "unknown command" in the shipped binary even though the
// implementation existed. Walk the real command tree from rootCmd, exactly as
// the shipped `keyorix` binary would resolve `keyorix encryption
// auth-encryption <subcommand>`.
import "testing"

func TestRootCmd_AuthEncryptionReachable(t *testing.T) {
	encCmd, _, err := rootCmd.Find([]string{"encryption"})
	if err != nil {
		t.Fatalf("rootCmd has no 'encryption' command: %v", err)
	}

	authCmd, _, err := rootCmd.Find([]string{"encryption", "auth-encryption"})
	if err != nil {
		t.Fatalf("'keyorix encryption auth-encryption' is unreachable from rootCmd: %v", err)
	}
	if authCmd.Parent() != encCmd {
		t.Fatalf("auth-encryption resolved but is not a child of the encryption command")
	}

	for _, sub := range []string{"status", "enable", "rotate", "migrate", "validate"} {
		if _, _, err := rootCmd.Find([]string{"encryption", "auth-encryption", sub}); err != nil {
			t.Errorf("'keyorix encryption auth-encryption %s' is unreachable: %v", sub, err)
		}
	}
}
